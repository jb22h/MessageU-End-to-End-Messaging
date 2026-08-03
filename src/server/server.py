import socket
import struct
import threading
import uuid
import datetime
from typing import Optional, Dict, Any, List, Tuple

# =========================
# Protocol constants
# =========================
VERSION = 1

# Request codes
CODE_REGISTER = 700
CODE_LIST_CLIENTS = 701
CODE_GET_PUBKEY = 702
CODE_SEND_MSG = 703
CODE_PULL_MSGS = 704

# Response codes
RES_REGISTER_OK = 2100
RES_LIST_CLIENTS = 2101
RES_PUBKEY = 2102
RES_MSG_STORED = 2103
RES_WAITING_MSGS = 2104
RES_ERROR = 9000

# Fixed field sizes (per spec)
NAME_FIELD_SIZE = 255
PUBKEY_SIZE = 160

# Request header: client_id(16) + version(u8) + code(u16) + payload_size(u32)
REQ_HEADER_FMT = "<16sBHI"
REQ_HEADER_SIZE = struct.calcsize(REQ_HEADER_FMT)

# Response header: version(u8) + code(u16) + payload_size(u32)
RES_HEADER_FMT = "<BHI"
RES_HEADER_SIZE = struct.calcsize(RES_HEADER_FMT)

# Defensive limit: reject oversized payloads
MAX_PAYLOAD = 10 * 1024 * 1024  # 10MB


# =========================
# TCP helpers
# =========================
def recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    """Receive exactly n bytes from TCP, or None if connection closed."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def send_all(sock: socket.socket, data: bytes) -> None:
    """Send all bytes (handles partial sends)."""
    view = memoryview(data)
    while len(view):
        sent = sock.send(view)
        if sent <= 0:
            raise ConnectionError("send failed")
        view = view[sent:]


def read_port() -> int:
    """Read port from myport.info (same folder). If missing -> default 1357 with warning."""
    default_port = 1357
    try:
        with open("myport.info", "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        print("[WARN] myport.info not found, using default {}".format(default_port))
        return default_port
    except Exception as e:
        print("[WARN] failed reading myport.info ({}), using default {}".format(e, default_port))
        return default_port


def build_response(code: int, payload: bytes) -> bytes:
    """Build protocol response: header + payload."""
    header = struct.pack(RES_HEADER_FMT, VERSION, code, len(payload))
    return header + payload


def pack_name_255(name: str) -> bytes:
    """Pack a username into a 255-byte null-terminated field."""
    b = name.encode("utf-8", errors="ignore")[:254]  # keep room for null terminator
    b = b + b"\x00"
    return b.ljust(NAME_FIELD_SIZE, b"\x00")


# =========================
# In-memory storage (RAM)
# =========================
lock = threading.Lock()

# client_id(bytes16) -> {"name": str, "pubkey": bytes, "last_seen": datetime}
clients_by_id: Dict[bytes, Dict[str, Any]] = {}

# username -> client_id(bytes16)
clients_by_name: Dict[str, bytes] = {}

# recipient_id(bytes16) -> list of (from_id, msg_id, msg_type, content_bytes)
messages_by_recipient: Dict[bytes, List[Tuple[bytes, int, int, bytes]]] = {}

# global incremental message id
next_msg_id = 1


def is_registered(client_id: bytes) -> bool:
    """Check if client_id exists in clients table."""
    with lock:
        return client_id in clients_by_id


# =========================
# Request handlers
# =========================
def handle_register(conn: socket.socket, payload: bytes) -> bytes:
    """700: Register client with name(255) + pubkey(160). Returns new UUID."""
    if len(payload) != NAME_FIELD_SIZE + PUBKEY_SIZE:
        return build_response(RES_ERROR, b"")

    raw_name = payload[:NAME_FIELD_SIZE]
    pubkey = payload[NAME_FIELD_SIZE:NAME_FIELD_SIZE + PUBKEY_SIZE]

    name_bytes = raw_name.split(b"\x00", 1)[0]
    name = name_bytes.decode("utf-8", errors="ignore").strip()
    if not name:
        return build_response(RES_ERROR, b"")

    with lock:
        # Reject duplicate username
        if name in clients_by_name:
            return build_response(RES_ERROR, b"")

        new_id = uuid.uuid4().bytes  # 16 bytes UUID
        clients_by_id[new_id] = {
            "name": name,
            "pubkey": pubkey,
            "last_seen": datetime.datetime.utcnow()
        }
        clients_by_name[name] = new_id
        # Ensure recipient queue exists
        messages_by_recipient.setdefault(new_id, [])

    return build_response(RES_REGISTER_OK, new_id)


def handle_list_clients(conn: socket.socket, client_id: bytes, payload: bytes) -> bytes:
    """701: Return list of clients (excluding requester). Payload must be empty."""
    if payload:
        return build_response(RES_ERROR, b"")
    if not is_registered(client_id):
        return build_response(RES_ERROR, b"")

    out = bytearray()
    with lock:
        for cid, info in clients_by_id.items():
            # Spec: do not include the client that requested the list
            if cid == client_id:
                continue
            out += cid
            out += pack_name_255(info["name"])

    return build_response(RES_LIST_CLIENTS, bytes(out))


def handle_get_pubkey(conn: socket.socket, client_id: bytes, payload: bytes) -> bytes:
    """702: Get public key for target client_id (payload=16)."""
    if len(payload) != 16:
        return build_response(RES_ERROR, b"")
    if not is_registered(client_id):
        return build_response(RES_ERROR, b"")

    target_id = payload
    with lock:
        info = clients_by_id.get(target_id)
        if info is None:
            return build_response(RES_ERROR, b"")
        pubkey = info["pubkey"]

    # payload: target_id + pubkey(160)
    return build_response(RES_PUBKEY, target_id + pubkey)


def handle_send_message(conn: socket.socket, client_id: bytes, payload: bytes) -> bytes:
    """703: Store message for recipient.
    payload: to_id(16) + msg_type(1) + content_size(4) + content
    """
    if len(payload) < 16 + 1 + 4:
        return build_response(RES_ERROR, b"")
    if not is_registered(client_id):
        return build_response(RES_ERROR, b"")

    to_id = payload[:16]
    msg_type = payload[16]
    content_size = struct.unpack("<I", payload[17:21])[0]
    content = payload[21:]

    # Defensive: content_size must match actual content length
    if content_size != len(content):
        return build_response(RES_ERROR, b"")

    global next_msg_id

    with lock:
        # Recipient must exist
        if to_id not in clients_by_id:
            return build_response(RES_ERROR, b"")

        mid = next_msg_id
        next_msg_id += 1

        messages_by_recipient.setdefault(to_id, []).append((client_id, mid, msg_type, content))

    # response payload: to_id + message_id(u32)
    return build_response(RES_MSG_STORED, to_id + struct.pack("<I", mid))


def handle_pull_messages(conn: socket.socket, client_id: bytes, payload: bytes) -> bytes:
    """704: Pull pending messages for this client. Payload must be empty.
    After returning messages, they are removed from the queue.
    """
    if payload:
        return build_response(RES_ERROR, b"")
    if not is_registered(client_id):
        return build_response(RES_ERROR, b"")

    # Copy and clear queue under lock
    with lock:
        to_send = messages_by_recipient.get(client_id, [])
        messages_by_recipient[client_id] = []

    # Build payload: repeated records
    # from_id(16) + msg_id(u32) + msg_type(u8) + content_size(u32) + content
    out = bytearray()
    for from_id, mid, msg_type, content in to_send:
        out += from_id
        out += struct.pack("<I", mid)
        out += bytes([msg_type])
        out += struct.pack("<I", len(content))
        out += content

    # If something fails while building the response, restore the queue
    try:
        return build_response(RES_WAITING_MSGS, bytes(out))
    except Exception:
        with lock:
            current = messages_by_recipient.get(client_id, [])
            messages_by_recipient[client_id] = to_send + current
        raise


# =========================
# Client thread loop
# =========================
def handle_client(conn: socket.socket, addr):
    """Handle a single TCP connection (supports multiple requests on the same connection)."""
    try:
        while True:
            header_bytes = recv_exact(conn, REQ_HEADER_SIZE)
            if header_bytes is None:
                return

            client_id, version, code, payload_size = struct.unpack(REQ_HEADER_FMT, header_bytes)

            # Defensive: reject huge payload sizes
            if payload_size > MAX_PAYLOAD:
                send_all(conn, build_response(RES_ERROR, b""))
                return

            payload = b""
            if payload_size:
                payload = recv_exact(conn, payload_size)
                if payload is None:
                    return

            # Enforce protocol version
            if version != VERSION:
                send_all(conn, build_response(RES_ERROR, b""))
                continue

            # Update last_seen for registered clients (except register)
            if code != CODE_REGISTER and is_registered(client_id):
                with lock:
                    clients_by_id[client_id]["last_seen"] = datetime.datetime.utcnow()

            # Dispatch by request code
            if code == CODE_REGISTER:
                res = handle_register(conn, payload)
            elif code == CODE_LIST_CLIENTS:
                res = handle_list_clients(conn, client_id, payload)
            elif code == CODE_GET_PUBKEY:
                res = handle_get_pubkey(conn, client_id, payload)
            elif code == CODE_SEND_MSG:
                res = handle_send_message(conn, client_id, payload)
            elif code == CODE_PULL_MSGS:
                res = handle_pull_messages(conn, client_id, payload)
            else:
                res = build_response(RES_ERROR, b"")

            send_all(conn, res)

    except Exception as e:
        print("[ERR] {}: {}".format(addr, e))
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    """Server main loop: bind, listen, accept, and spawn threads for clients."""
    port = read_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    print("[OK] server listening on 0.0.0.0:{}".format(port))

    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
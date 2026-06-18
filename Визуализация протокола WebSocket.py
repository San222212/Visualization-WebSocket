import socket
import ssl
import base64
import hashlib
import random
import time
import threading

# WEBSOCKET КЛИЕНТ С ЛОКАЛЬНЫМ СЕРВЕРОМ

def print_line():
    print("=" * 60)

def print_header(text):
    print_line()
    print(f"  {text}")
    print_line()

def wait_enter():
    input("\nНажми Enter чтобы продолжить:")

def log(message, emoji="•"):
    print(f"\n{emoji} {message}")
    time.sleep(0.3)

# РАБОТА С КЛЮЧАМИ

def generate_key():
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    rand_str = ""
    for _ in range(16):
        rand_str += random.choice(chars)
    return base64.b64encode(rand_str.encode()).decode()

def calculate_accept(ws_key):
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    combined = ws_key + GUID
    sha = hashlib.sha1(combined.encode()).digest()
    return base64.b64encode(sha).decode()

# ЛОКАЛЬНЫЙ ТЕСТОВЫЙ СЕРВЕР

class SimpleWebSocketServer:
    
    def __init__(self, host='localhost', port=8765):
        self.host = host
        self.port = port
        self.server_socket = None
        self.is_running = False
        self.client_socket = None
        
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        self.server_socket.settimeout(1)
        self.is_running = True
        
        print(f"Тестовый сервер запущен на ws://{self.host}:{self.port}")
        
        server_thread = threading.Thread(target=self._run, daemon=True)
        server_thread.start()
        
    def _run(self):
        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"Клиент подключился: {address}")
                self.client_socket = client_socket
                self._handle_client(client_socket)
                self.client_socket = None
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"Ошибка сервера: {e}")
                break
    
    def _handle_client(self, client_socket):
        try:
            # Увеличиваем таймаут
            client_socket.settimeout(30)
            
            # Читаем HTTP запрос
            request_data = b""
            while b"\r\n\r\n" not in request_data:
                try:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        print("Клиент отключился")
                        return
                    request_data += chunk
                except socket.timeout:
                    print("Таймаут при чтении запроса")
                    return
            
            request_text = request_data.decode(errors='ignore')
            
            # Извлекаем ключ
            ws_key = None
            for line in request_text.split('\r\n'):
                if line.lower().startswith('sec-websocket-key:'):
                    ws_key = line.split(':', 1)[1].strip()
                    break
            
            if not ws_key:
                print("Ключ не найден")
                client_socket.close()
                return
            
            # Отправляем ответ 101
            accept_key = calculate_accept(ws_key)
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_key}\r\n"
                "\r\n"
            )
            
            client_socket.send(response.encode())
            
            # Цикл обмена сообщениями
            while self.is_running:
                try:
                    message = self._read_frame(client_socket)
                    
                    if message is None:
                        print("Клиент закрыл соединение")
                        break
                    
                    if message and message != "":
                        print(f"Получено от клиента: {message}")
                        response_text = f"Эхо: {message}"
                        self._send_frame(client_socket, response_text)
                        print(f"Отправлен овтет: {response_text}")
                    
                except socket.timeout:
                    continue
                except ConnectionError:
                    print("Соединение разорвано")
                    break
                except OSError as e:
                    # Ошибка сокета - соединение закрыто
                    if e.winerror == 10053:
                        print("Клиент отключился")
                    else:
                        print(f"Ошибка сокета: {e}")
                    break
                except Exception as e:
                    print(f"Ошибка: {e}")
                    break
                    
        except Exception as e:
            print(f"Ошибка сервера: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            print("Соединение с клиентом закрыто")
    
    def _read_frame(self, sock):
        try:
            # Читаем первые 2 байта
            header = b""
            while len(header) < 2:
                chunk = sock.recv(2 - len(header))
                if not chunk:
                    return None
                header += chunk
            
            opcode = header[0] & 0x0F
            length = header[1] & 0x7F
            is_masked = (header[1] >> 7) & 1
            
            if opcode == 0x8:
                # Отправляем подтверждение закрытия
                try:
                    close_frame = bytes([0x88, 0x00])
                    sock.send(close_frame)
                except:
                    pass
                return None
            
            if opcode == 0x9:
                pong = bytes([0x8A, 0x00])
                sock.send(pong)
                return ""
            
            if length == 126:
                extra = sock.recv(2)
                length = (extra[0] << 8) | extra[1]
            elif length == 127:
                extra = sock.recv(8)
                length = 0
                for b in extra:
                    length = (length << 8) | b
            
            mask = b""
            if is_masked:
                mask = sock.recv(4)
            
            data = b""
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            
            if is_masked and mask:
                unmasked = bytearray()
                for i, byte in enumerate(data):
                    unmasked.append(byte ^ mask[i % 4])
                data = bytes(unmasked)
            
            if opcode == 0x1:  
                text = data.decode('utf-8', errors='ignore')
                if text.startswith("Эхо:"):
                    return ""
                return text
            
        except socket.timeout:
            raise
        except:
            return None
    
    def _send_frame(self, sock, text):
        data = text.encode('utf-8')
        length = len(data)
        frame = bytearray()
        
        frame.append(0x81)
        
        if length < 126:
            frame.append(length)
        elif length < 65536:
            frame.append(126)
            frame.extend([(length >> 8) & 0xFF, length & 0xFF])
        else:
            frame.append(127)
            for i in range(7, -1, -1):
                frame.append((length >> (8 * i)) & 0xFF)
        
        frame.extend(data)
        sock.send(bytes(frame))
    
    def stop(self):
        self.is_running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

# ПОДКЛЮЧЕНИЕ К СЕРВЕРУ

def create_socket(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    print(f"Подключаюсь к {host}:{port}...")
    sock.connect((host, port))
    print("Соединение установлено")
    
    return sock

def make_handshake(sock, host, path):
    my_key = generate_key()
    
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {my_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    
    try:
        sock.send(request.encode())
        
        # Получаем ответ
        response = b""
        sock.settimeout(5)
        
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                return False
            response += chunk
        
        if b"101" in response:
            print("WebSocket соединение установлено")
            sock.settimeout(30)
            return True
        else:
            print("Ошибка рукопожатия")
            return False
            
    except Exception as e:
        print(f"Ошибка: {e}")
        return False

# ФРЕЙМЫ

def encode_frame(text):
    data = text.encode('utf-8')
    length = len(data)
    frame = bytearray()
    
    frame.append(0x81)
    
    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend([(length >> 8) & 0xFF, length & 0xFF])
    else:
        frame.append(0x80 | 127)
        for i in range(7, -1, -1):
            frame.append((length >> (8 * i)) & 0xFF)
    
    mask = [random.randint(0, 255) for _ in range(4)]
    frame.extend(mask)
    
    for i, byte in enumerate(data):
        frame.append(byte ^ mask[i % 4])
    
    return bytes(frame)

def decode_frame(sock):
    try:
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                return None, None
            header += chunk
        
        opcode = header[0] & 0x0F
        length = header[1] & 0x7F
        
        if opcode == 0x8:
            return None, 'close'
        
        if length == 126:
            extra = sock.recv(2)
            length = (extra[0] << 8) | extra[1]
        elif length == 127:
            extra = sock.recv(8)
            length = 0
            for b in extra:
                length = (length << 8) | b
        
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        
        if opcode == 0x1:
            return data.decode('utf-8', errors='ignore'), 'text'
        
        return data, 'unknown'
        
    except socket.timeout:
        print("Таймаут ожидания")
        return None, None
    except:
        return None, None

# ОТПРАВКА И ПОЛУЧЕНИЕ

def send_message(sock, text):
    try:
        frame = encode_frame(text)
        sock.send(frame)
        print(f"Отправлено: '{text}'")
        return True
    except Exception as e:
        print(f"Ошибка: {e}")
        return False

def receive_message(sock):
    try:
        sock.settimeout(2.0)
        data, msg_type = decode_frame(sock)
        
        if msg_type == 'text' and data:
            print(f"Получено: '{data}'")
            return data
        elif msg_type == 'close':
            print("Сервер закрыл соединение")
            return None
            
    except socket.timeout:
        pass
    except Exception as e:
        print(f"Ошибка: {e}")
    
    return None

def close_connection(sock):
    try:
        # Отправляем фрейм закрытия
        close_frame = bytes([0x88, 0x80, 0x00, 0x00, 0x00, 0x00])
        sock.send(close_frame)
        print("Отправлен фрейм закрытия")
        time.sleep(0.3)
    except:
        pass
    
    try:
        sock.close()
        print("Соединение закрыто")
    except:
        pass

# ДЕМОНСТРАЦИЯ

def show_demo(server):
    print_header("ДЕМОНСТРАЦИЯ WEBSOCKET ПРОТОКОЛА")
    
    print("\nWebSocket позволяет обмениваться данными")
    print("между клиентом и сервером в реальном времени.\n")
    print(f"Сервер: ws://{server.host}:{server.port}\n")
    wait_enter()
    
    # Шаг 1
    log("ШАГ 1: Адрес сервера", "1️⃣")
    print("WebSocket URL: ws://localhost:8765")
    print("ws:// - нешифрованное соединение")
    print("wss:// - шифрованное соединение")
    wait_enter()
    
    # Шаг 2
    log("ШАГ 2: Создание сокета", "2️⃣")
    print("Сокет = точка соединения")
    print("TCP гарантирует доставку данных")
    wait_enter()
    
    # Шаг 3
    log("ШАГ 3: Подключение", "3️⃣")
    sock = create_socket(server.host, server.port)
    wait_enter()
    
    # Шаг 4
    log("ШАГ 4: Рукопожатие", "4️⃣")
    
    if not make_handshake(sock, server.host, "/"):
        print("Не удалось подключиться")
        sock.close()
        wait_enter()
        return
    
    wait_enter()
    
    # Шаг 5
    log("ШАГ 5: Отправка сообщений", "5️⃣")
    
    messages = ["Привет!", "Как дела?", "WebSocket крутой!"]
    
    for i, msg in enumerate(messages, 1):
        print(f"\nСообщение {i}: '{msg}'")
        
        if send_message(sock, msg):
            time.sleep(0.5)
            receive_message(sock)
        
        wait_enter()
    
    # Шаг 6 - правильное закрытие
    log("ШАГ 6: Закрытие соединения", "6️⃣")
    print("Отправляем фрейм закрытия (0x88)")
    print("и ждем подтверждения от сервера...")
    
    close_connection(sock)
    
    print("\nДемонстрация завершена!")
    wait_enter()

def show_help():
    print_header("СПРАВКА ПО КОМАНДАМ")
    
    print("\n┌─────────────────────────────────────┐")
    print("│  КОМАНДА  │  ОПИСАНИЕ               │")
    print("├─────────────────────────────────────┤")
    print("│    1      │  Показать справку       │")
    print("│    2      │  Подключиться к серверу │")
    print("│    3      │  Отправить сообщение    │")
    print("│    4      │  Показать состояние     │")
    print("│    5      │  Демонстрация протокола │")
    print("│    6      │  В главное меню         │")
    print("└─────────────────────────────────────┘")
    
    print("\n💡 Совет по последовательности:")
    print("  1. Подключитесь (команда 2)")
    print("  2. Отправьте сообщение (команда 3)")
    print("  3. Сервер ответит автоматически")
    print_line()

def interactive_mode(server):
    print_header("ИНТЕРАКТИВНЫЙ РЕЖИМ")
    print(f"Сервер: ws://{server.host}:{server.port}")
    print("Введите 1 для показа справки\n")
    
    sock = None
    connected = False
    
    while True:
        try:
            cmd = input("Команда > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nВыход...")
            break
        
        if cmd == "1":
            show_help()
            
        elif cmd == "2":
            if connected:
                print("Уже подключены!")
                continue
            
            try:
                sock = create_socket(server.host, server.port)
                time.sleep(0.2)
                
                if make_handshake(sock, server.host, "/"):
                    connected = True
                    print("Готово!")
                else:
                    sock.close()
                    sock = None
            except Exception as e:
                print(f"Ошибка: {e}")
                if sock:
                    sock.close()
                sock = None
                
        elif cmd == "3":
            if not connected or not sock:
                print("Сначала подключитесь!")
                continue
            
            text = input("Текст сообщения: ").strip()
            if text:
                if send_message(sock, text):
                    time.sleep(0.5)
                    receive_message(sock)
            else:
                print("Пустое сообщение")
                
        elif cmd == "4":
            if connected:
                print(f"\nСтатус: Подключено")
                print(f"Сервер: {server.host}:{server.port}")
            else:
                print(f"\nСтатус: Не подключено")
                
        elif cmd == "5":
            if sock:
                close_connection(sock)
                sock = None
                connected = False
            show_demo(server)
            
        elif cmd == "6":
            if sock:
                close_connection(sock)
                sock = None
            print("Возврат в меню...")
            break
            
        else:
            print("Неизвестная команда, проверьте список команд (1)")

def main():
    
    print("Запуск сервера...")
    server = SimpleWebSocketServer('localhost', 8765)
    server.start()
    time.sleep(0.5)
    
    try:
        while True:
            print("\n" * 2)
            print_header("ГЛАВНОЕ МЕНЮ")
            print(f"Сервер: ws://{server.host}:{server.port}")
            print("\n  1 - Интерактивный режим")
            print("  2 - Демонстрация")
            print("  3 - Выход")
            print_line()
            
            choice = input("\nВыбор: ").strip()
            
            if choice == "1":
                interactive_mode(server)
            elif choice == "2":
                show_demo(server)
            elif choice == "3":
                print("\nВыход...")
                break
            else:
                print("Неверный выбор, выберете из списка")
                
    finally:
        server.stop()
        print("Программа завершена")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nОстановлено")
    except Exception as e:
        print(f"\nОшибка: {e}")
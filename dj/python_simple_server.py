# import socket
#
# server = socket.create_server(("127.0.0.1", 8000))
# server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#
# server.listen(10)
# try:
#     while True:
#         client_socket, address = server.accept()
#         # из байта в стр
#         received_data = client_socket.recv(1024).decode('utf-8')
#         print(f"after python server.py command server was started and reseived data is {received_data}")
#         # пример простого сервера на питоне
#         # типо можно набросав такой скрипт увидеть данные которые тебе прилетают в запросе
#         # пример того, как можно вернуть ответ в браузер
#         path = received_data.split(" ")[1]
#         response = f"HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\n\n" \
#                    f"Привет </br>Path: {path}"
#         # из стр в байт
#         client_socket.send(response.encode("utf-8"))
# except KeyboardInterrupt:
#     # команды чтобы остановить сервер
#     server.shutdown(socket.SHUT_RDWR)
#     server.close()

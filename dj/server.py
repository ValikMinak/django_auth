"""пример того как логинить юзера c помощью кук и цифровой подписи на fastAPI"""
import base64
import hmac
import hashlib
from typing import Optional
import json
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

# openssl rand -hex 32 -- соль для цифровой подписи куки
SECRET_KEY = "c38d8b4bf2343db4a3ecdd2332c32c06b1622d268de61a870d365ba6eab5614e"
# openssl rand -hex 32 -- соль для паролей
PASSWORD_SALT = "96abd99c191a653c22343cd4b2c394fd4e44835dc33f02aee67c1ab99c286d71"


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256(("my_passwrd_23" + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    print(password_hash)
    print(stored_password_hash)
    return password_hash == stored_password_hash


users = {
    "Valentyn": {
        "name": "Valentyn",
        "password": "d43ed759329002a414ef5919d36e2d65aabe4a478e64e41ca628f7312d5258c4",  # == my_passwrd_23
        # сделать пароль c солью  hashlib.sha256(("my_passwrd_23" + PASSWORD_SALT).encode()).hexdigest()
        "balance": 75000
    }
}


def get_username_from_signed_str(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def sign_data(data: str) -> str:
    """ :return signed data """
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    """захожу на главную и проверяю есть ли в куке юзернейм
    если нету, то отправляю на стр логина и там
    если есть, то достаю из куки раскодированный юзернейм
    если юзернеймы совпадают то ок иначе удалить куку с таким ключом
    """
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_str(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Hello {users[valid_username]['name']}", media_type='text/html')


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    """
    получаю данные из формы и проверяю есть ли такой юзер в базе
    создаю закодированную куку
    :param username:
    :param password:
    :return:
    """
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Wrong credantials"
            }),
            media_type='application/json'
        )

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello {users[username]['name']}!"
        }),
        media_type='application/json'
    )
    "создаю подпись из закодированного юзернейма и его хеша и устанавливаю ее в куку под ключом username"
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response

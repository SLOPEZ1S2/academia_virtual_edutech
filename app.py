import os
import json
import uuid
import hmac, hashlib
import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response, stream_with_context
from dotenv import load_dotenv
from openai import OpenAI
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET_KEY", "dev-secret")


CULQI_PK = os.getenv("CULQI_PK")
CULQI_SK = os.getenv("CULQI_SK")
TOKENS_URL  = "https://api.culqi.com/v2/tokens"
CHARGES_URL = "https://api.culqi.com/v2/charges"


PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID")
PAYPAL_SECRET    = os.getenv("PAYPAL_SECRET")
PAYPAL_BASE      = "https://api-m.sandbox.paypal.com"


COINBASE_API_KEY = os.getenv("COINBASE_API_KEY")
COINBASE_WEBHOOK_SECRET = os.getenv("COINBASE_WEBHOOK_SECRET")
COINBASE_BASE = "https://api.commerce.coinbase.com"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") 

PRODUCTS = [
    {"id": 1, "name": "Python Básico",   "price": 15000, "duration": "3 semanas"},
    {"id": 2, "name": "Flask Pro",       "price": 20000, "duration": "4 semanas"},
    {"id": 3, "name": "Django Avanzado", "price": 25000, "duration": "6 semanas"},
]



USERS = {"admin": "1234"}

def cart_total():
    cart = session.get("cart", [])
    return sum(p["price"] for p in cart)

# ------------------- AUTH -------------------
@app.route("/")
def root():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username in USERS and USERS[username] == password:
            session["user"] = username
            session.setdefault("cart", [])
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Credenciales incorrectas")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ------------------- TIENDA -------------------

# ------------------- DASHBOARD -------------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    total = cart_total()
    return render_template("dashboard.html", products=PRODUCTS, total=total)


@app.route("/shop")
def shop():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("shop.html", products=PRODUCTS)

@app.route("/cart")
def cart():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("cart.html", cart=session.get("cart", []))

@app.route("/add_to_cart/<int:pid>")
def add_to_cart(pid: int):
    if "user" not in session:
        return redirect(url_for("login"))
    prod = next((p for p in PRODUCTS if p["id"] == pid), None)
    if prod:
        c = session.get("cart", [])
        c.append(prod)
        session["cart"] = c
    return redirect(url_for("cart"))

@app.route("/clear_cart")
def clear_cart():
    session["cart"] = []
    return redirect(url_for("cart"))

# ------------------- CHECKOUT -------------------
@app.route("/checkout")
def checkout():
    if "user" not in session:
        return redirect(url_for("login"))
    total = cart_total()
    return render_template("checkout.html", total=total)

@app.route("/pay/card")
def pay_card():
    if "user" not in session:
        return redirect(url_for("login"))
    total = cart_total()
    return render_template("pay_card.html", total=total)

@app.route("/pay/wallet")
def pay_wallet():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("pay_wallet.html")

@app.route("/pay/crypto")
def pay_crypto():
    if "user" not in session:
        return redirect(url_for("login"))
    total = cart_total()
    return render_template("pay_crypto.html", total=total)

@app.route("/pay/paypal")
def pay_paypal():
    if "user" not in session:
        return redirect(url_for("login"))
    total = cart_total()
    return render_template(
        "pay_paypal.html",
        total=total,
        PAYPAL_CLIENT_ID=PAYPAL_CLIENT_ID
    )


# ------------------- CULQI -------------------
@app.route("/api/culqi/token", methods=["POST"])
def culqi_token():
    payload = request.get_json(force=True) or {}
    headers = {"Authorization": f"Bearer {CULQI_PK}", "Content-Type": "application/json"}
    r = requests.post(TOKENS_URL, headers=headers, json=payload, timeout=30)
    return jsonify(r.json()), r.status_code

@app.route("/api/payments/charge", methods=["POST"])
def culqi_charge():
    payload = request.get_json(force=True) or {}
    headers = {"Authorization": f"Bearer {CULQI_SK}", "Content-Type": "application/json"}
    data = {
        "amount": payload.get("amount", 0),
        "currency_code": payload.get("currency", "PEN"),
        "email": payload.get("email"),
        "source_id": payload.get("token_id"),
        "description": "Compra en Academia Virtual"
    }
    r = requests.post(CHARGES_URL, headers=headers, json=data, timeout=30)
    if 200 <= r.status_code < 300:
        session["cart"] = []
    return jsonify(r.json()), r.status_code

@app.route("/webhook/culqi", methods=["POST"])
def webhook_culqi():
    return "", 200

# ------------------- PAYPAL -------------------
def paypal_get_access_token():
    r = requests.post(
        f"{PAYPAL_BASE}/v1/oauth2/token",
        auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET),
        data={"grant_type": "client_credentials"},
        headers={"Accept": "application/json"}
    )
    r.raise_for_status()
    return r.json()["access_token"]

@app.route("/paypal/create-order", methods=["POST"])
def paypal_create_order():
    try:
        access_token = paypal_get_access_token()
        total_pen = cart_total() / 100.0
        tipo_cambio = 3.8
        total_usd = round(total_pen / tipo_cambio, 2)

        if total_usd <= 0:
            return jsonify({"ok": False, "error": "Monto inválido"}), 400

        order = {
            "intent": "CAPTURE",
            "purchase_units": [{
                "amount": {"currency_code": "USD", "value": f"{total_usd:.2f}"}
            }],
            "application_context": {
                "user_action": "PAY_NOW",
                "shipping_preference": "NO_SHIPPING"
            }
        }

        r = requests.post(
            f"{PAYPAL_BASE}/v2/checkout/orders",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json=order, timeout=30
        )
        data = r.json()

        if "id" in data:
            return jsonify({"ok": True, "id": data["id"], "paypal_raw": data}), 200
        else:
            return jsonify({"ok": False, "paypal_error": data}), r.status_code
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/paypal/capture-order/<order_id>", methods=["POST"])
def paypal_capture_order(order_id):
    try:
        access_token = paypal_get_access_token()
        r = requests.post(
            f"{PAYPAL_BASE}/v2/checkout/orders/{order_id}/capture",
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            timeout=30
        )
        data = r.json()
        if r.ok:
            session["cart"] = []
            return jsonify({"ok": True, "capture": data}), 200
        else:
            return jsonify({"ok": False, "paypal_error": data}), r.status_code
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ------------------- COINBASE -------------------
@app.route("/coinbase/create-charge", methods=["POST"])
def coinbase_create_charge():
    total_pen = cart_total() / 100.0
    tipo_cambio = 3.8
    total_usd = round(total_pen / tipo_cambio, 2)

    headers = {
        "X-CC-Api-Key": COINBASE_API_KEY,
        "X-CC-Version": "2018-03-22",
        "Content-Type": "application/json"
    }
    data = {
        "name": "Academia Virtual",
        "description": "Compra de cursos",
        "pricing_type": "fixed_price",
        "local_price": {"amount": f"{total_usd:.2f}", "currency": "USD"},
        "metadata": {"cart_id": str(uuid.uuid4())}
    }
    r = requests.post(f"{COINBASE_BASE}/charges", headers=headers, json=data, timeout=30)
    return jsonify(r.json()), r.status_code

@app.route("/webhook/coinbase", methods=["POST"])
def webhook_coinbase():
    payload = request.get_data()
    signature = request.headers.get("X-CC-Webhook-Signature", "")
    computed_signature = hmac.new(
        COINBASE_WEBHOOK_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_signature, signature):
        return jsonify({"ok": False, "error": "Firma inválida"}), 400

    data = request.get_json(force=True)
    event_type = data.get("event", {}).get("type")
    charge_code = data.get("event", {}).get("data", {}).get("code")

    print(f"🔔 Webhook Coinbase recibido: {event_type} (charge {charge_code})")

    if event_type == "charge:confirmed":
        session["cart"] = []
        print("✅ Pago confirmado en Coinbase")

    return jsonify({"ok": True}), 200




# Inicializa el cliente de OpenAI con la clave
client = OpenAI(api_key=OPENAI_API_KEY)

def _ensure_history():
    cursos_texto = "\n".join(
        [f"- {p['name']} (S/ {p['price']/100:.2f}, duración: {p['duration']})" for p in PRODUCTS]
    )

    metodos_pago = "- Tarjeta (Culqi)\n- Yape/Plin\n- PayPal\n- Criptomonedas (Coinbase)"

    system_message = f"""
Eres el asistente oficial de la Academia Virtual.
Tu tarea es ayudar a los estudiantes a obtener información sobre cursos y métodos de pago.

CUIDADO:
- Solo debes hablar de los cursos que aparecen en esta lista.
- Si el usuario pregunta por un curso que NO existe, responde: 
  "Ese curso no está disponible actualmente. Los cursos disponibles son:" y luego lista los cursos.
- Nunca inventes cursos o precios.
- Si preguntan métodos de pago, responde exactamente esta lista.

CURSOS DISPONIBLES:
{cursos_texto}

MÉTODOS DE PAGO:
{metodos_pago}

Tu tono debe ser amable, claro y breve.
"""

    if "chat_history" not in session:
        session["chat_history"] = [{"role": "system", "content": system_message}]
    else:
        # Mantiene memoria corta para bajar consumo
        session["chat_history"] = session["chat_history"][:1] + session["chat_history"][-6:]

@app.route("/consultar_chatgpt", methods=["POST"])
def consultar_chatgpt():
    if "user" not in session:
        return jsonify({"error": "No autorizado"}), 401

    pregunta = request.json.get("pregunta", "").strip()
    if not pregunta:
        return jsonify({"error": "Pregunta vacía"}), 400

    _ensure_history()

    history = list(session["chat_history"])
    history.append({"role": "user", "content": pregunta})

    respuesta_completa = ""

    @stream_with_context
    def generate():

# es la encargada de recibir la respuesta de la IA en streaming y enviarla 
# hacia el navegador poco a poco, para que el usuario vea cómo la IA "escribe en vivo".
        nonlocal respuesta_completa
        
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=history,
                stream=True
            )

            for chunk in response:
                if chunk.choices and chunk.choices[0].delta.content:
                    fragmento = chunk.choices[0].delta.content
                    respuesta_completa += fragmento
                    yield fragmento
        
        finally:
            # Guardar memoria mientras todavia hay request context
            session["chat_history"].append({"role": "user", "content": pregunta})
            session["chat_history"].append({"role": "assistant", "content": respuesta_completa})
            session.modified = True

    return Response(generate(), mimetype="text/plain")




# ------------------- MAIN -------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

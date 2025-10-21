from flask import Flask, request, jsonify
import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import logging

app = Flask(__name__)

# =============================
# 🔹 Configuration Logging
# =============================

# Configuration du logging vers fichier
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/banking-app.log'),
        logging.StreamHandler()  # Affiche aussi dans la console
    ]
)

logger = logging.getLogger(__name__)

# =============================
# 🔹 Configuration
# =============================

DB_CONFIG = {
    'host': '10.0.0.13',         # VM PostgreSQL
    'port': 5432,
    'database': 'banking_db',
    'user': 'banking_user',
    'password': 'SecureP@ss2025!'  # Mot de passe PostgreSQL
}

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "azizdaoues20@gmail.com"
SMTP_PASS = "lbae ltxz nshs vjqw"

# MODE DÉVELOPPEMENT : Affiche le code MFA dans les logs
DEV_MODE = True  # Mettre à False pour envoyer les vrais emails

# Stockage temporaire des codes MFA
mfa_codes = {}  # { "username": {"code":123456, "expire":datetime} }

# =============================
# 🔹 Fonctions utilitaires
# =============================

def get_db_connection():
    """Connexion à PostgreSQL"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        logger.info("✅ Connexion DB établie")
        return conn
    except Exception as e:
        logger.error(f"❌ Erreur connexion DB: {e}")
        return None

def hash_password(password):
    """Hash SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def send_email(to_email, subject, body, username, code):
    """Envoi d'un email via Gmail"""
    
    # MODE DÉVELOPPEMENT : Afficher le code dans les logs
    if DEV_MODE:
        logger.warning(f"🔓 MODE DEV - Code MFA pour {username}: {code}")
        logger.info(f"📧 Email destinataire: {to_email}")
        print("\n" + "="*60)
        print(f"🔐 CODE MFA POUR {username.upper()}")
        print(f"📧 Destinataire: {to_email}")
        print(f"🔢 Code: {code}")
        print("="*60 + "\n")
        return True
    
    # MODE PRODUCTION : Envoi réel de l'email
    try:
        msg = MIMEText(body)
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        
        logger.info(f"✅ Email MFA envoyé à {to_email}")
        return True
    except Exception as e:
        logger.error(f"❌ Erreur envoi email : {e}")
        return False

# =============================
# 🔹 Routes API Authentification
# =============================

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logger.info(f"🔑 Tentative connexion: {username} depuis {client_ip}")

    if not username or not password:
        logger.warning(f"⚠️ Champs manquants pour {username}")
        return jsonify({"status": "error", "message": "Champs manquants"}), 400

    conn = get_db_connection()
    if not conn:
        logger.error("❌ Erreur serveur BDD")
        return jsonify({"status": "error", "message": "Erreur serveur BDD"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, email, role, password_hash 
            FROM users 
            WHERE username = %s
        """, (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            logger.warning(f"❌ Échec authentification: utilisateur {username} introuvable")
            return jsonify({"status": "error", "message": "Utilisateur introuvable"}), 401

        if user["password_hash"] != hash_password(password):
            logger.warning(f"❌ Échec authentification: mot de passe incorrect pour {username}")
            return jsonify({"status": "error", "message": "Mot de passe incorrect"}), 401

        # Log succès vérification identifiants
        logger.info(f"✅ Identifiants vérifiés pour {username} (Role: {user['role']}, Email: {user['email']})")

        # Générer le code MFA
        code = random.randint(100000, 999999)
        expire = datetime.now() + timedelta(minutes=5)
        mfa_codes[username] = {"code": code, "expire": expire, "role": user["role"]}

        logger.info(f"🔐 Code MFA généré pour {username}")

        body = f"""
Bonjour {username},

Votre code MFA est : {code}
Il est valable 5 minutes.

-- Système Bancaire Sécurisé
"""
        if send_email(user["email"], "Votre code MFA", body, username, code):
            logger.info(f"✅ Processus MFA initié pour {username}")
            return jsonify({"status": "ok", "mfa_required": True}), 200
        else:
            logger.error(f"❌ Échec envoi MFA pour {username}")
            return jsonify({"status": "error", "message": "Erreur envoi email"}), 500

    except Exception as e:
        logger.error(f"❌ Erreur /login: {e}")
        return jsonify({"status": "error", "message": "Erreur serveur"}), 500


@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    data = request.json
    username = data.get('username')
    code = data.get('code')
    
    logger.info(f"🔍 Tentative vérification MFA pour: {username}")

    if username not in mfa_codes:
        logger.warning(f"⚠️ Code MFA inexistant pour {username}")
        return jsonify({"status": "error", "message": "Aucun code MFA actif"}), 401

    record = mfa_codes[username]
    if datetime.now() > record["expire"]:
        logger.warning(f"⏰ Code MFA expiré pour {username}")
        del mfa_codes[username]
        return jsonify({"status": "error", "message": "Code expiré"}), 401

    if str(code) == str(record["code"]):
        role = record["role"]
        del mfa_codes[username]
        logger.info(f"✅ Connexion réussie: {username} - Role: {role}")
        return jsonify({"status": "ok", "role": role}), 200
    else:
        logger.warning(f"❌ Code MFA incorrect pour {username}")
        return jsonify({"status": "error", "message": "Code incorrect"}), 401

# =============================
# 🔹 Autres routes API
# =============================

@app.route('/api/comptes', methods=['GET'])
def get_comptes():
    """Liste tous les comptes actifs"""
    logger.info("📊 Requête: Liste des comptes")
    
    conn = get_db_connection()
    if not conn:
        logger.error("❌ Erreur base de données")
        return jsonify({"status": "error", "message": "Erreur base de données"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT c.id, c.numero_compte, c.type_compte, c.solde, c.devise, c.statut,
                   cl.nom, cl.prenom, cl.email
            FROM comptes c
            JOIN clients cl ON c.client_id = cl.id
            WHERE c.statut = 'actif'
            ORDER BY cl.nom;
        """)
        comptes = cur.fetchall()
        cur.close()
        conn.close()
        
        logger.info(f"✅ {len(comptes)} comptes retournés")
        return jsonify({"status": "ok", "comptes": comptes}), 200
    except Exception as e:
        logger.error(f"❌ Erreur /api/comptes: {e}")
        return jsonify({"status": "error", "message": "Erreur serveur"}), 500


@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Historique des transactions récentes"""
    limit = request.args.get('limit', 50)
    logger.info(f"📜 Requête: Historique transactions (limit={limit})")
    
    conn = get_db_connection()
    if not conn:
        logger.error("❌ Erreur DB")
        return jsonify({"status": "error", "message": "Erreur DB"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT t.id, t.montant, t.type_transaction, t.description, 
                   t.date_transaction, cs.numero_compte AS compte_source,
                   cd.numero_compte AS compte_dest
            FROM transactions t
            LEFT JOIN comptes cs ON t.compte_source_id = cs.id
            LEFT JOIN comptes cd ON t.compte_dest_id = cd.id
            ORDER BY t.date_transaction DESC
            LIMIT %s;
        """, (limit,))
        transactions = cur.fetchall()
        cur.close()
        conn.close()
        
        logger.info(f"✅ {len(transactions)} transactions retournées")
        return jsonify({"status": "ok", "transactions": transactions}), 200
    except Exception as e:
        logger.error(f"❌ Erreur /api/transactions: {e}")
        return jsonify({"status": "error", "message": "Erreur serveur"}), 500


@app.route('/api/virement', methods=['POST'])
def virement():
    """Effectuer un virement entre deux comptes"""
    data = request.json
    source = data.get('compte_source_id')
    dest = data.get('compte_dest_id')
    montant = data.get('montant')
    description = data.get('description', '')
    
    logger.info(f"💸 Tentative virement: {montant} de compte {source} vers {dest}")

    if not all([source, dest, montant]):
        logger.warning("⚠️ Virement: champs manquants")
        return jsonify({"status": "error", "message": "Champs manquants"}), 400

    conn = get_db_connection()
    if not conn:
        logger.error("❌ Erreur DB")
        return jsonify({"status": "error", "message": "Erreur DB"}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT solde FROM comptes WHERE id = %s", (source,))
        solde = cur.fetchone()
        
        if not solde or solde["solde"] < float(montant):
            logger.warning(f"⚠️ Solde insuffisant pour compte {source}")
            return jsonify({"status": "error", "message": "Solde insuffisant"}), 400

        cur.execute("BEGIN;")
        cur.execute("UPDATE comptes SET solde = solde - %s WHERE id = %s;", (montant, source))
        cur.execute("UPDATE comptes SET solde = solde + %s WHERE id = %s;", (montant, dest))
        cur.execute("""
            INSERT INTO transactions (compte_source_id, compte_dest_id, montant, type_transaction, description)
            VALUES (%s, %s, %s, 'virement', %s)
            RETURNING id;
        """, (source, dest, montant, description))
        
        transaction_id = cur.fetchone()['id']
        cur.execute("COMMIT;")

        cur.close()
        conn.close()
        
        logger.info(f"✅ Virement réussi - Transaction #{transaction_id} - Montant: {montant}")
        return jsonify({"status": "ok", "message": "Virement effectué", "transaction_id": transaction_id}), 200

    except Exception as e:
        logger.error(f"❌ Erreur /api/virement: {e}")
        if conn:
            conn.rollback()
        return jsonify({"status": "error", "message": "Erreur lors du virement"}), 500


@app.route('/logout', methods=['POST'])
def logout():
    """Déconnexion"""
    logger.info("👋 Déconnexion utilisateur")
    return jsonify({"status": "ok", "message": "Déconnexion réussie"}), 200


@app.route('/health', methods=['GET'])
def health():
    """Vérifie si le backend est actif"""
    return jsonify({"status": "ok", "message": "Backend opérationnel"}), 200


# =============================
# 🔹 Lancement de l'application
# =============================
if __name__ == '__main__':
    logger.info("🚀 Démarrage du serveur Flask - Système Bancaire Sécurisé")
    app.run(host='0.0.0.0', port=5000)

import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['hash'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    import uuid
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

# UI
st.title("🔏 Secure Data  Encryption & Storage App")

menu = ["Home", "Encrypt Data", "Decrypt Data", "login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Too many attempts? Force login
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = 'login'
    st.warning("🔏Too many failed attempts. Please confirm your identity & login again!")

# Pages
if st.session_state.current_page == "Home":
    st.subheader("🎉 Welcome to the Secure Data Encryption & Storage App! 🎊")
    st.write("This app allows you to securely encrypt and store your data without leaking your privacy.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Encrypt Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Decrypt Data")

    st.info(f"🔒 Currently storing {len(st.session_state.stored_data)} encrypted data entries.")

elif st.session_state.current_page == "Encrypt Data":
    st.subheader("🔒 Store New Data")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a passkey to encrypt the data:", type="password")
    confirm_passkey = st.text_input("Confirm your passkey:", type="password")

    if st.button("Encrypt & Store Data"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("🚩 Passkeys do not match. Please try again.")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_data = encrypt_data(user_data, passkey)

                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_data,
                    "hash": hashed_passkey,
                }

                st.success("✔ Data stored successfully!")
                st.code(data_id, language='text')
                st.info("🔑 Keep this ID safe to retrieve your data later.")
        else:
            st.error("🚩 All fields are required!")

elif st.session_state.current_page == "Decrypt Data":
    st.subheader("🔑 Retrieve Data")

    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"Attempts remaining: {attempts_remaining}")

    data_id = st.text_input("Enter the data ID to retrieve:")
    passkey = st.text_input("Enter the passkey to decrypt the data:", type="password")

    if st.button("Decrypt Data"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success("✔ Data retrieved successfully!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language='text')
                else:
                    st.error(f"🚩 Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("🚨 Data ID not found!")
        else:
            st.warning("🚩 Both fields are required!")

        if st.session_state.failed_attempts >= 3:
            st.warning("🔒 Too many failed attempts. Please confirm your identity & login again!")
            st.session_state.current_page = 'login'
            st.rerun()

elif st.session_state.current_page == "login":
    st.subheader("🔑 Reauthorization Required")

    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attempts >= 3:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Please wait {remaining_time} seconds before trying again.")
    else:
        login_pass = st.text_input("Enter your passkey to reauthorize:", type="password")
        if st.button("Login"):
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("✔ Login successful!")
                st.session_state.current_page = 'Home'
                st.rerun()
            else:
                st.error("❌ Incorrect passkey.")

# Footer
st.markdown("---")
st.markdown("### 🔒 Secure Data Encryption | Educational Project")

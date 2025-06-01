import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# Function to generate a hash passkey!
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()
def generate_key_from_passkey(passkey):
# Generate a consistent key from the passkey
    hashed = hashlib.sha256(passkey.encode()).digest()
# Ensure it's valid for fernet to Generate a (32-url-safe base64-encoded bytes)
    return base64.urlsafe_b64encode(hashed[:32])

# Function to encrypt data!
def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data!
def decrypt_data(encrypted_text, passkey,data_id):
    try:
        hased_passkey =hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['hash'] == hased_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            #increment the failed attempts if the passkey or data ID is incorrect!
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
        return None
    except Exception as e:
        # If decryption fails, increment the failed attempts
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None
# Function to genrate a unique ID for data secure!
def generate_data_id():
    import uuid
    return str(uuid.uuid4())

# Function to reset failed attempts!
def reset_failed_attempts():
    st.session_state.failed_attempts = 0
    # Function to change the current page!
def change_page(page):
    st.session_state.current_page = page

    # For Streamlit UI!
st.title("🔏 Secure Data  Encryption & Storage App")

# Navigation
menu = ["Home", "Encrypt Data", "Decrypt Data", "login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))

# Update the current page in session state based on the sidebar selection!
st.session_state.current_page = choice

# Check if to many failed attempts!
if st.session_state.failed_attempts >= 3:
      #forced redirect to login page!          
    st.session_state.current_page = 'login'
    st.warning("🔏Too many failed attempts. please confirm Your identity & login again!")

# Function to display the current page!
if st.session_state.current_page == "Home":
    st.subheader("🎉Welcome to the Secure Data Encryption & Storage App!🎊")
    st.write("This app allows you to securely encrypt and store your data without leaked your privacy.")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")

    # Display store data count!
    st.info(f"🔒 Currently storing {len(st.session_state.stored_data)} encrypted data entries.")

elif st.session_state.current_page == "Store Data":
    st.subheader("🔒 Store New Data")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a passkey to encrypt the data:", type="password")
    confirm_passkey = st.text_input("Confirm your passkey:", type="password")

    if st.button("Encrypt & Store Data"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error(" 🚩 Passkeys do not match. Please try again.")
            else:
                data_id = generate_data_id()

                # Hash the passkey for storage!
                hashed_passkey = hash_passkey(passkey)

                # Encrypt the data!
                encrypted_data = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_data": encrypted_data,
                    "hash": hashed_passkey,
                }

                st.success(" ✔ Data stored successfully!")
                st.code(data_id, language='text')
                st.info("🔑 Keep this ID safe to retrieve your data later.")
        else:
            st.error("🚩 All fields are required!")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔑 Retrieve Data")

#Show attempts left!
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.info(f"attempts_remaining: {attempts_remaining}")

    data_id = st.text_input("Enter the data ID to retrieve:")
    passkey = st.text_input("Enter the passkey to decrypt the data:", type="password")

    if st.button("Decrypt Data"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                    encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                    decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                    if decrypted_text:
                       st.success("✔ Data retrieved successfully!")
                       st.markdown("### your Decrypted Data:")
                       st.code(decrypted_text, language='text')
                    else:
                        st.error(f"🚩 Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                        st.error("🚩 Failed to decrypt the data. Please check your passkey or data ID.")
            else:
                st.error("🚨Data ID not found!")


        # Check if too many failed attempts after this attempt!
        if st.session_state.failed_attempts >= 3:
            st.warning("🔒 Too many failed attempts. Please confirm your identity & login again!")
            st.session_state.current_page = 'login'
            st.rerun()
        else:
            st.warning(" 🚩Both fields are required!.")

elif st.session_state.current_page == "login":
     st.subheader("🔑 Reauthoraization Required")

     # Add a simple timeout mechanism!
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

# Add a footer!
st.markdown("---")
st.markdown("### 🔒 Secure Data Encryption | Educational Project")
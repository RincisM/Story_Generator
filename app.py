import streamlit as st
from streamlit_option_menu import option_menu
from streamlit_lottie import st_lottie
import json
import firebase_admin
import hashlib
from firebase_admin import credentials, auth, firestore
from transformers import GPT2LMHeadModel, GPT2Tokenizer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load pre-trained GPT-2 model and tokenizer
model_name = "gpt2"
model = GPT2LMHeadModel.from_pretrained(model_name)
tokenizer = GPT2Tokenizer.from_pretrained(model_name)

# Function to generate story
def generate_story(prompt, length=300):
    input_ids = tokenizer.encode(prompt, return_tensors="pt", max_length=1024)
    outputs = model.generate(input_ids, max_length=length, num_beams=5, no_repeat_ngram_size=2, top_k=20, top_p=0.98)
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return generated_text

# Function to encrypt data using AES
def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return encrypted_data

# Function to decrypt data using AES
def decrypt_data(encrypted_data, key):
    cipher = Cipher(algorithms.AES(key), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode()

# Firebase initialization (ensure single call throughout your app)
cred = credentials.Certificate('./story-generator-sdk.json')
if not firebase_admin._apps:  # Check if app is already initialized
    firebase_admin.initialize_app(cred)

# Function to check if the user is logged in
def is_user_logged_in():
    return 'user_email' in st.session_state

# Authentication functions
def signup(name, email, password):
    try:
        user = auth.create_user(email=email, password=password, display_name=name)
        # Store user data in Firestore
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        custom_claims = {"password_hash": password_hash}
        auth.set_custom_user_claims(user.uid, custom_claims)
        user_data = {"name": name, "email": email, "password_hash": password_hash}
        firestore.client().collection("users").document(user.uid).set(user_data)
        st.success("Account created successfully. Go to Login Page")
    except Exception as e:
        st.error(f"Error: {e}")

# Authentication functions
def login(email, password):
    try:
        user = auth.get_user_by_email(email)
        custom_claims = user.custom_claims
        password_hash = custom_claims.get("password_hash") if custom_claims else None
        entered_hash = hashlib.sha256(password.encode()).hexdigest()  # Hash entered password
        if entered_hash == password_hash:
            st.session_state['user_email'] = user.email
            st.success(f"Welcome, {st.session_state['user_email']}! You may proceed with the Home Page")
        else:
            st.error("Invalid Password")
    except auth.UserNotFoundError:
        st.error("User not found.")
    except Exception as e:
        st.error(f"Error: {e}")

# Function to logout
def logout():
    if is_user_logged_in():
        del st.session_state['user_email']
        st.success("Logged out successfully.")
    else:
        st.warning("You are not logged in.")

# Function to save encrypted story in Firestore
def save_story(user_email, prompt, story, encryption_key):
    encrypted_story = encrypt_data(story, encryption_key)
    user_ref = firestore.client().collection("users").where("email", "==", user_email).stream()
    for user_doc in user_ref:
        user_id = user_doc.id
        story_data = {"prompt": prompt, "story": encrypted_story}
        firestore.client().collection("stories").document(user_id).collection("user_stories").add(story_data)

# Function to retrieve and decrypt stories from Firestore
def get_user_stories(user_email, encryption_key):
    user_ref = firestore.client().collection("users").where("email", "==", user_email).stream()
    for user_doc in user_ref:
        user_id = user_doc.id
        stories_ref = firestore.client().collection("stories").document(user_id).collection("user_stories").stream()
        user_stories = []
        for story in stories_ref:
            prompt = story.get("prompt")
            encrypted_story = story.get("story")
            decrypted_story = decrypt_data(encrypted_story, encryption_key)
            user_stories.append({"prompt": prompt, "story": decrypted_story})
        return user_stories

# Set page configuration
st.set_page_config(page_title="Story Generator", layout="wide")


# Streamlit app interface
def main():
    st.markdown(
        """
        <div style="text-align: center;">
            <h1 style="color: #1E88E5;">Story Generator</h1>
            <br>
        </div>
        """,
        unsafe_allow_html=True,
    )

    selected_nav = option_menu(
        menu_title=None,
        options=["Home", "Your Stories", "Login/Logout"],
        default_index=0,
        orientation="horizontal",
    )

    if selected_nav == "Login/Logout":
        selected_nav_mini = option_menu(
            menu_title=None,
            options=["Login", "Signup", "Logout"],
            default_index=0,
            orientation="horizontal",
        )
        if selected_nav_mini == "Login":
            login_page()
        elif selected_nav_mini == "Signup":
            signup_page()
        elif selected_nav_mini == "Logout":
            if st.button("Logout"):
                logout()
    elif selected_nav == "Home":
        home_page()
    elif selected_nav == "Your Stories":
        your_stories_page()

def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

def home_page():
    lottie_coding = load_lottiefile("animations/Studying_Kids.json")
    if is_user_logged_in():
        st.markdown(
            """
            <div style="text-align: center;">
                <h2>Welcome to the Story Generator</h2>
                <p>This interactive app empowers you to unleash your creativity by generating unique stories based on your prompts</p>
                <p>Visit our Github Page by clicking <a href="https://github.com/RincisM/Story_Generator/tree/main" target="_blank">here</a></p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        prompt = st.text_input("Enter a starting prompt:")

        # Generate and display story
        if st.button("Generate Story"):
            if prompt:
                story = generate_story(prompt)
                st.write(story)
                encryption_key = hashlib.sha256(st.session_state['user_email'].encode()).digest()[:16]
                save_story(st.session_state['user_email'], prompt, story, encryption_key) 
            else:
                st.warning("Please enter a prompt.")
        st.divider()
        st_lottie(lottie_coding)

    else:
        st.warning("You need to log in first.")
        st.divider()
        st_lottie(lottie_coding)

def your_stories_page():
    if is_user_logged_in():
        encryption_key = hashlib.sha256(st.session_state['user_email'].encode()).digest()[:16]
        user_stories = get_user_stories(st.session_state['user_email'], encryption_key)
        st.header("Your Generated Stories")
        for story in user_stories:
            st.write(f"Prompt: {story['prompt']}")
            st.write(story['story'])
            st.markdown("---")
    else:
        st.warning("You need to log in first.")

def signup_page():
    lottie_coding = load_lottiefile("animations/Hello.json")
    columns = st.columns([2, 1])  # Two columns with a ratio of 2:1

    # Column 1: Login details
    with columns[0]:
        st.header("Sign Up")
        name = st.text_input("Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")

        if st.button("Sign Up"):
            signup(name, email, password)

    # Column 2: Image
    with columns[1]:
        st_lottie(lottie_coding)

def login_page():
    lottie_coding = load_lottiefile("animations/Hello.json")

    columns = st.columns([2, 1])  # Two columns with a ratio of 2:1

    # Column 1: Login details
    with columns[0]:
        st.header("Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            login(email, password)

    # Column 2: Image
    with columns[1]:
        st_lottie(lottie_coding)


if __name__ == "__main__":
    main()

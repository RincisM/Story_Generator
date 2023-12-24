import streamlit as st
from streamlit_option_menu import option_menu
import firebase_admin
import hashlib
from firebase_admin import credentials, auth, firestore
from transformers import GPT2LMHeadModel, GPT2Tokenizer

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
        user_data = {"name": name, "email": email, "password_hash": password_hash}
        firestore.client().collection("users").document(user.uid).set(user_data)
        st.success("Account created successfully")
    except Exception as e:
        st.error(f"Error: {e}")

# Authentication functions
def login(email, password):
    try:
        user = auth.get_user_by_email(email)
        password_hash = user.password_hash
        entered_hash = hashlib.sha256(password.encode()).hexdigest()  # Hash entered password
        if entered_hash == password_hash:
            st.session_state['user_email'] = user.email
            st.success(f"Welcome, {st.session_state['user_email']}!")
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

# Function to save story in Firestore
def save_story(user_email, prompt, story):
    user_ref = firestore.client().collection("users").where("email", "==", user_email).stream()
    for user_doc in user_ref:
        user_id = user_doc.id
        story_data = {"prompt": prompt, "story": story}
        firestore.client().collection("stories").document(user_id).collection("user_stories").add(story_data)

# Function to retrieve stories from Firestore
def get_user_stories(user_email):
    user_ref = firestore.client().collection("users").where("email", "==", user_email).stream()
    for user_doc in user_ref:
        user_id = user_doc.id
        stories_ref = firestore.client().collection("stories").document(user_id).collection("user_stories").stream()
        user_stories = [{"prompt": story.get("prompt"), "story": story.get("story")} for story in stories_ref]
        return user_stories

# Streamlit app interface
def main():
    st.title("Story Generator")

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

def home_page():
    if is_user_logged_in():
        st.header("Home Page")
        st.write("Welcome to the Home Page! You can add your content here.")
        prompt = st.text_input("Enter a starting prompt:")

        # Generate and display story
        if st.button("Generate Story"):
            if prompt:
                story = generate_story(prompt)
                st.write(story)
                save_story(st.session_state['user_email'], prompt, story) 
            else:
                st.warning("Please enter a prompt.")

    else:
        st.warning("You need to log in first.")

def your_stories_page():
    if is_user_logged_in():
        user_stories = get_user_stories(st.session_state['user_email'])
        st.header("Your Generated Stories")
        for story in user_stories:
            st.write(f"Prompt: {story['prompt']}")
            st.write(story['story'])
            st.markdown("---")
    else:
        st.warning("You need to log in first.")

def signup_page():
    st.header("Sign Up")
    name = st.text_input("Name")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Sign Up"):
        signup(name, email, password)

def login_page():
    st.header("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        login(email, password)

if __name__ == "__main__":
    main()

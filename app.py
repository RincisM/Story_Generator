import streamlit as st

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

# Streamlit app interface
st.title("Story Generator")

# User input
prompt = st.text_input("Enter a starting prompt:")

# Generate and display story
if st.button("Generate Story"):
    if prompt:
        story = generate_story(prompt)
        st.write(story)
    else:
        st.warning("Please enter a prompt.")
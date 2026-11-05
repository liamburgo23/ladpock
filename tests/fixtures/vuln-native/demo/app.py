import gradio as gr
import streamlit as st

demo = gr.Interface(fn=lambda x: x, inputs="text", outputs="text")
demo.launch(share=True)
st.markdown(user_text, unsafe_allow_html=True)

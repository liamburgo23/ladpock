import gradio as gr
import streamlit as st

demo = gr.Interface(fn=lambda x: x, inputs="text", outputs="text")
demo.launch(server_name="127.0.0.1")
team = gr.Interface(fn=lambda x: x, inputs="text", outputs="text")
team.launch(share=True, auth=("team", password))
st.write(user_text)
st.markdown("<style>body { color: red }</style>", unsafe_allow_html=True)

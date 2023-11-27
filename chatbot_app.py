import streamlit as st
from transformers import AutoTokenizer, pipeline
import requests
import re
import virustotal_python
import torch
import os

class Chatbot:
    def __init__(self, modelo, nvd_api_key, vt_api_key):
        self.modelo = modelo
        self.tokenizador = AutoTokenizer.from_pretrained(modelo)
        self.llama_pipeline = pipeline(
            "text-generation",
            model=modelo,
            torch_dtype=torch.float16,
            device_map="auto",
        )
        self.nvd_api_key = nvd_api_key
        self.vt_api_key = vt_api_key

    def obtener_respuesta_llama(self, prompt):
        secuencias = self.llama_pipeline(
            prompt,
            do_sample=True,
            top_k=10,
            num_return_sequences=1,
            eos_token_id=self.tokenizador.eos_token_id,
            max_length=256,
        )
        return secuencias[0]['generated_text']

class Manejador:
    @staticmethod
    def manejar_entrada_usuario(chatbot, entrada_usuario):
        prompt = f"Muy interesados en temas de ciberseguridad, pregunta: {entrada_usuario}"
        return prompt

class Visualizador:
    def __init__(self):
        st.title("Chatbot de Ciberseguridad")
        self.entrada_usuario = st.text_input("Usuario:", placeholder="Escribe tu mensaje aquí...")
        self.boton_enviar = st.button("Enviar")
        self.respuesta_chat = st.empty()

    def mostrar_respuesta(self, respuesta):
        self.respuesta_chat.markdown(f"**Chatbot:** {respuesta}")

    def mostrar_widgets(self):
        pass  # No es necesario en Streamlit

class Main:
    # Variable global para almacenar la instancia de Chatbot
    chatbot = None

    @staticmethod
    def inicializar_chatbot():
        # Configuración inicial
        modelo_nombre = "meta-llama/Llama-2-7b-chat-hf"
        nvd_api_key = st.secrets["nvd_api_key"]
        vt_api_key = st.secrets["vt_api_key"]
        Main.chatbot = Chatbot(modelo_nombre, nvd_api_key, vt_api_key)

    @staticmethod
    def main():
        # Inicializar el chatbot una sola vez
        if Main.chatbot is None:
            Main.inicializar_chatbot()

        # Crear instancias de las clases
        manejador = Manejador()
        visualizador = Visualizador()

        # Manejar y mostrar respuesta al hacer clic en el botón
        if visualizador.boton_enviar:
            entrada_usuario = visualizador.entrada_usuario.strip()
            prompt = manejador.manejar_entrada_usuario(Main.chatbot, entrada_usuario)
            respuesta = Main.chatbot.obtener_respuesta_llama(prompt)
            visualizador.mostrar_respuesta(respuesta)

# Ejecutar la aplicación
if __name__ == "__main__":
    Main.main()

from transformers import AutoTokenizer, pipeline
import streamlit as st
import requests
import re
import virustotal_python
import torch

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
        contexto_nvd = GestorContexto.obtener_info_cve(chatbot, entrada_usuario)
        contexto_vt = GestorContexto.obtener_info_vt(chatbot, entrada_usuario)

        prompt = f"Muy interesados en temas de ciberseguridad, pregunta: {entrada_usuario}"

        if contexto_nvd:
            prompt += f"\n\nContexto de la National Vulnerability Database (NVD):\n{contexto_nvd}"

        if contexto_vt:
            prompt += f"\n\nContexto del análisis realizado por VirusTotal: {contexto_vt}"

        if entrada_usuario.lower() in ["adios", "salir", "salida"]:
            return "¡Hasta luego!"

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

class GestorContexto:
    @staticmethod
    def obtener_info_cve(chatbot, entrada_usuario):
        coincidencias_cve_id = re.findall(r'(CVE-\d{4}-\d{4,7})', entrada_usuario)

        if coincidencias_cve_id:
            cve_id = coincidencias_cve_id[0]

            url_peticion_nvd_api = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}?cpeMatchString=&pubStartDate=&pubEndDate=&modStartDate=&modEndDate=&maxResults=1&startIndex=0"
            encabezados = {"Apikey": chatbot.nvd_api_key}
            respuesta_nvd = requests.get(url_peticion_nvd_api, headers=encabezados)

            if respuesta_nvd.status_code == 200:
                datos_nvd = respuesta_nvd.json()
                if 'result' in datos_nvd and 'CVE_Items' in datos_nvd['result']:
                    cve_item = datos_nvd['result']['CVE_Items'][0]
                    descripcion_cve = cve_item['cve']['description']['description_data'][0]['value']
                    fecha_publicacion_cve = cve_item['publishedDate']

                    return f"CVE-ID: {cve_id}\nDescripción: {descripcion_cve}\nFecha de publicación: {fecha_publicacion_cve}"

        return ""

    @staticmethod
    def obtener_info_vt(chatbot, entrada_usuario):
        if "vt" in entrada_usuario.lower():
            consulta_vt = entrada_usuario.replace("vt", "").strip()
            with virustotal_python.Virustotal(chatbot.vt_api_key) as vtotal:
                try:
                    if GestorContexto.es_ip_valida(consulta_vt):
                        respuesta = vtotal.request(f"ip_addresses/{consulta_vt}")
                    else:
                        respuesta = vtotal.request(f"domains/{consulta_vt}")

                    # Muestra la información del informe y devuelve los resultados formateados
                    return GestorContexto.formato_respuesta_virustotal(respuesta.data)

                except virustotal_python.VirustotalError as err:
                    print(f"Fallo al obtener información de {consulta_vt} en VirusTotal: {err}")

        return None

    @staticmethod
    def formato_respuesta_virustotal(respuesta):
        resultados_formateados = []

        if 'attributes' in respuesta and 'last_analysis_results' in respuesta['attributes']:
            resultados = respuesta['attributes']['last_analysis_results']

            for motor, info_resultado in resultados.items():
                resultado_formateado = {
                    'Motor': motor,
                    'Categoría': info_resultado['category'],
                    'Método': info_resultado['method'],
                    'Resultado': info_resultado['result']
                }
                resultados_formateados.append(resultado_formateado)

        return resultados_formateados

    @staticmethod
    def es_ip_valida(ip):
        try:
            partes = ip.split(".")
            return len(partes) == 4 and all(0 <= int(parte) < 256 for parte in partes)
        except ValueError:
            return False

class Main:
    # Variable global para almacenar la instancia de Chatbot
    chatbot = None

    @staticmethod
    def inicializar_chatbot():
        # Configuración inicial
        modelo_nombre = "meta-llama/Llama-2-7b-chat-hf"
        nvd_api_key = "dfb96c0d-42b1-404a-b728-b60209f60d1e"
        vt_api_key = "545891483e42526711e00e3c420a71fb8cf75d5a6248b50a7dfcc0255a770c66"

        # Crear instancia de la clase Chatbot
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

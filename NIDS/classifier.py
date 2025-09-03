import tensorflow as tf
import pandas as pd
import numpy as np
import keras
import psycopg2
import os
from sqlalchemy import create_engine
from typing import Dict
from sklearn import preprocessing
import time

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "nids_db")
DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")

LABEL_MAPPING = {0: "Botnet", 1: "Bruteforce", 2: "DoS", 3: "Normal", 4: "Scan"}
MALICIOUS_CLASSES = {"Botnet", "Bruteforce", "DoS", "Scan"}

def conectar():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

def get_sqlalchemy_engine():
    return create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

def check_table_size(table_name: str, engine) -> int:
    query = f"SELECT COUNT(*) FROM {table_name}"
    with engine.connect() as conn:
        result = conn.execute(query)
        count = result.scalar()
    return count


class Classifier:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.label_mapping = LABEL_MAPPING
        self.connection = conectar()
        self.engine = get_sqlalchemy_engine()

    def load_data(self):
        try:
            df = pd.read_sql("SELECT flow_id, src_ip, dest_ip, src_port, dest_port, proto, hour, minute, seconds, severity, pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient FROM trafego ORDER BY id DESC LIMIT 300", self.engine)
            if not df.empty:
                return df
            else:
                print("[Classifier] Nenhum dado encontrado na tabela 'trafego'.")
                return None
        except Exception as e:
            raise RuntimeError(f"[Classifier] Erro ao carregar dados: {e}")

    def encode_data(self, df: pd.DataFrame):
        df_encoded = df.copy()
        categorical_columns = df_encoded.select_dtypes(include=["object"]).columns
        for col in categorical_columns:
            df_encoded[col] = df_encoded[col].astype('category').cat.codes
        return df_encoded

    def preprocess_data(self, df: pd.DataFrame):
        df = df.dropna()
        df_encoded = self.encode_data(df)
        try:
            X = df_encoded.drop(columns=["class"])
            return X, df_encoded
        except:
            X = df_encoded
            return X, df_encoded

    def load_model(self):
        if os.path.exists(self.model_path):
            return keras.models.load_model(self.model_path)
        else:
            raise FileNotFoundError("[Classifier] Modelo não encontrado.")

    def predict(self, model, X: pd.DataFrame, threshold: float = 0.7):
        scaler = preprocessing.StandardScaler()
        X = scaler.fit_transform(X)
        X = X.reshape(X.shape[0], X.shape[1], 1)
        predictions = model.predict(X)
        confidences = np.max(predictions, axis=1)
        predicted_temp = np.argmax(predictions, axis=1)
        predicted_indices = np.where(confidences >= threshold, predicted_temp, 3)  # 3 = Normal
        predicted_classes = [self.label_mapping[i] for i in predicted_indices]
        print(f"[Classifier] Predições realizadas com sucesso.\n{predicted_classes}")
        return predicted_classes

    def save_malicious_predictions(self, original_df: pd.DataFrame, predicted_classes: list):
        original_df["class"] = predicted_classes
        maliciosos = original_df[original_df["class"].isin(MALICIOUS_CLASSES)]

        if maliciosos.empty:
            print("[Classifier] Nenhum tráfego malicioso detectado.")
            return

        try:
            maliciosos.to_sql("classificados", self.engine, if_exists="append", index=False, method='multi')
            print(f"[Classifier] {len(maliciosos)} registros maliciosos salvos na tabela 'classificados'.")
        except Exception as e:
            raise RuntimeError(f"[Classifier] Erro ao salvar predições: {e}")

    def run(self):
        print("[Classifier] Carregando dados do banco...")
        df = self.load_data()
        if df is None:
            print("[Classifier] Nenhum dado encontrado. Encerrando.")
            return

        print("[Classifier] Pré-processando dados...")
        X, df_original = self.preprocess_data(df)

        print("[Classifier] Carregando modelo...")
        model = self.load_model()
        model.summary()
        print("[Classifier] Modelo carregado com sucesso.")

        print("[Classifier] Realizando predições...")
        predictions = self.predict(model, X)

        print("[Classifier] Salvando predições maliciosas...")
        self.save_malicious_predictions(df, predictions)

if __name__ == "__main__":
    sleep_time = int(os.getenv("SLEEP_TIME", 60))
    while(True):
        try:
            model_path = os.getenv("MODEL_PATH", "/models/flower-uiot.keras")
            classifier = Classifier(model_path)
            classifier.run()
            print(f"[Classifier] Aguardando {sleep_time} segundos para a próxima execução")
            time.sleep(sleep_time)
            print("[Classifier] Encerrando o Classifier.")
        except Exception as e:
            print(f"[Classifier] Erro: {e}")
            time.sleep(5)
    
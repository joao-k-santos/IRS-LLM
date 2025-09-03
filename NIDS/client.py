import argparse
import os
from pathlib import Path

import flwr as fl
import tensorflow as tf
from tensorflow import keras
from flwr_datasets import FederatedDataset
import pandas as pd
from sklearn.model_selection import train_test_split
from keras.models import Sequential
from keras.layers import Flatten, Dense, Conv1D, MaxPool1D, Dropout, Input, Activation
from sklearn import preprocessing
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from imblearn.pipeline import Pipeline
from sklearn.utils import class_weight
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix

# Make TensorFlow logs less verbose
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"


# Define Flower client
class CifarClient(fl.client.NumPyClient):
    def __init__(self, model, x_train, y_train, x_test, y_test,new):
        self.model = model
        self.new = new
        self.x_train, self.y_train = x_train, y_train
        self.x_test, self.y_test = x_test, y_test
        self.y_pred = 0
        self.y_pred_bool = 0
        self.y_pred_b = 0
        self.visualizer = 0

    def get_properties(self, config):
        """Get properties of client."""
        raise Exception("Not implemented")

    def get_parameters(self, config):
        """Get parameters of the local model."""
        return self.model.get_weights()

    def fit(self, parameters, config):
        """Train parameters on the locally held training set."""

        # Update local model parameters
        self.model.set_weights(parameters)

        # Get hyperparameters for this round
        batch_size: int = config["batch_size"]
        epochs: int = config["local_epochs"]
        validation_split: float = config["validation_split"]

        # Train the model using hyperparameters from config
        history = self.model.fit(
            self.x_train,
            self.y_train,
            batch_size,
            epochs,
            validation_split=validation_split,
        )
        self.y_pred = self.model.predict(self.x_test, batch_size=32, verbose=2)
        self.y_pred_bool = np.argmax(self.y_pred, axis=-1)
        confusion = confusion_matrix(self.y_test, self.y_pred_bool)
        print('Confusion Matrix\n')
        print(confusion)

        print('\nClassification Report\n')
        print(classification_report(self.y_test, self.y_pred_bool, target_names = ['Botnet', 'Bruteforce', 'DoS', 'Normal', 'Scan']))

        self.y_pred = self.model.predict(self.new, batch_size=32)
        self.y_pred = np.argmax(self.y_pred, axis=-1)
        print(self.y_pred)

        with open('results/val.txt', 'w') as f:
            for line in self.y_pred:
                f.write(f"{line}\n")

        # Return updated model parameters and results
        parameters_prime = self.model.get_weights()
        num_examples_train = len(self.x_train)
        results = {
            "loss": history.history["loss"][0],
            "accuracy": history.history["accuracy"][0],
            "val_loss": history.history["val_loss"][0],
            "val_accuracy": history.history["val_accuracy"][0],
        }
        return parameters_prime, num_examples_train, results

    def evaluate(self, parameters, config):
        """Evaluate parameters on the locally held test set."""

        # Update local model with global parameters
        self.model.set_weights(parameters)

        # Get config values
        steps: int = config["val_steps"]

        # Evaluate global model parameters on the local test data and return results
        loss, accuracy = self.model.evaluate(self.x_test, self.y_test, 32, steps=steps)
        acc = accuracy * 100
        lss = loss * 100
        with open('results/accloss.txt', 'w') as f:
            f.write(f"{acc}\n")
            f.write(f"{lss}\n")

        num_examples_test = len(self.x_test)
        return loss, num_examples_test, {"accuracy": accuracy}


def main() -> None:
    # Parse command line argument `partition`
    parser = argparse.ArgumentParser(description="Flower")
    # parser.add_argument(
    #     "--client-id",
    #     type=int,
    #     default=0,
    #     choices=range(0, 10),
    #     required=True,
    #     help="Specifies the artificial data partition of CIFAR10 to be used. "
    #     "Picks partition 0 by default",
    # )
    # parser.add_argument(
    #     "--toy",
    #     action="store_true",
    #     help="Set to true to quicky run the client using only 10 datasamples. "
    #     "Useful for testing purposes. Default: False",
    # )
    parser.add_argument("--partition",type=int, choices=range(0, 10), required=True)
    parser.add_argument("--address",type=str,required=True)
    args = parser.parse_args()

    # Load and compile Keras model
    model = Sequential()
    model.add(Conv1D(filters=16, kernel_size=(3,), activation='relu', input_shape = (14,1)))
    model.add(Conv1D(filters=32, kernel_size=(3,), activation='relu', input_shape = (14,1)))
    model.add(MaxPool1D(pool_size=(3,), strides=2, padding='same'))
    model.add(Dropout(0.2))
    model.add(Flatten())
    model.add(Dense(32,activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(16,activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(5,activation='softmax'))

    opt = keras.optimizers.Adam(learning_rate=0.0001)
    model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])

    # Load a subset of CIFAR-10 to simulate the local data partition
    new = pd.read_csv('./received_file.csv', on_bad_lines='skip')
    new = encode(new)
    scaler = preprocessing.StandardScaler()
    new=scaler.fit_transform(new)
    new = new.reshape(new.shape[0], new.shape[1], 1)
    x_train, y_train, x_test, y_test = load_partition()

    # if args.toy:
    #     x_train, y_train = x_train[:10], y_train[:10]
    #     x_test, y_test = x_test[:10], y_test[:10]

    # Start Flower client
    client = CifarClient(model, x_train, y_train, x_test, y_test,new).to_client()

    fl.client.start_client(
        server_address=args.address,
        client=client,
        root_certificates=Path(".cache/certificates/ca.crt").read_bytes(),
    )


def load_partition():
    """Load 1/10th of the training and test data to simulate a partition."""
    # Download and partition dataset
    out = pd.read_csv('./trainmodel.csv', on_bad_lines='skip')
    out = encode(out)
    out['class'] = out['class'].astype('category')
    out['class'] = out['class'].cat.codes
    x = out.drop('class', axis=1)
    y = out.iloc[:,-1].values
    over = SMOTE(sampling_strategy={0: 3400, 1: 3300, 3: 2900, 4: 2800})
    under = RandomUnderSampler(sampling_strategy={2: 6500})
    pipeline = Pipeline(steps=[('u', under),('o', over)])
    x, y = pipeline.fit_resample(x, y)
    x_train, x_test, y_train, y_test = train_test_split(x,y,test_size=0.25,random_state=80)
    counter = Counter(y_train)
    scaler = preprocessing.StandardScaler()
    x_train=scaler.fit_transform(x_train)
    x_test=scaler.transform(x_test)
    x_train = x_train.reshape(x_train.shape[0], x_train.shape[1], 1)
    x_test = x_test.reshape(x_test.shape[0], x_test.shape[1], 1)

    # fds = FederatedDataset(dataset="cifar10", partitioners={"train": 10})
    # partition = fds.load_partition(idx)
    # partition.set_format("numpy")

    # # Divide data on each node: 80% train, 20% test
    # partition = partition.train_test_split(test_size=0.2, seed=42)
    # x_train, y_train = partition["train"]["img"] / 255.0, partition["train"]["label"]
    # x_test, y_test = partition["test"]["img"] / 255.0, partition["test"]["label"]
    return x_train, y_train, x_test, y_test

def encode(out):
    out['src_ip'] = out['src_ip'].astype('category')
    out['dest_ip'] = out['dest_ip'].astype('category')
    out['proto'] = out['proto'].astype('category')
    out['src_ip'] = out['src_ip'].cat.codes
    out['dest_ip'] = out['dest_ip'].cat.codes
    out['proto'] = out['proto'].cat.codes

    return out



if __name__ == "__main__":
    main()
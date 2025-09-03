from pathlib import Path
import argparse
from typing import Dict, Optional, Tuple, Callable, List, Tuple, Union
from flwr.common.logger import log
from flwr.common import Scalar, FitRes, Parameters, EvaluateRes
from flwr.server.client_manager import ClientManager
from flwr.server.client_proxy import ClientProxy
import numpy as np
import keras
import argparse
import flwr as fl
import tensorflow as tf
import pandas as pd
from sklearn.model_selection import train_test_split
from keras.models import Sequential
from keras.layers import Flatten, Dense, Conv1D, MaxPool1D, Dropout, Input, Activation
import client
from flwr_datasets import FederatedDataset

class SaveModelStrategy(fl.server.strategy.FaultTolerantFedAvg):
    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[fl.server.client_proxy.ClientProxy, fl.common.FitRes]],
        failures: List[Union[Tuple[ClientProxy, FitRes], BaseException]],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:

        # Call aggregate_fit from base class (FedAvg) to aggregate parameters and metrics
        aggregated_parameters, aggregated_metrics = super().aggregate_fit(server_round, results, failures)

        if aggregated_parameters is not None:
            # Convert 'Parameters' to 'List[np.ndarray]'
            aggregated_ndarrays: List[np.ndarray] = fl.common.parameters_to_ndarrays(aggregated_parameters)
            # Save aggregated_ndarrays
            print(f"Saving round {server_round} aggregated_ndarrays...")
            np.savez(f"round-{server_round}-weights.npz", *aggregated_ndarrays)

        return aggregated_parameters, aggregated_metrics

    def aggregate_evaluate(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, EvaluateRes]],
        failures: List[Union[Tuple[ClientProxy, FitRes], BaseException]],
    ) -> Tuple[Optional[float], Dict[str, Scalar]]:
        # Aggregate evaluation accuracy using weighted average.

        if not results:
            return None, {}

        # Call aggregate_evaluate from base class (FedAvg) to aggregate loss and  metrics
        aggregated_loss, aggregate_metrics = super().aggregate_evaluate(server_round, results, failures)

        # Weigh accuracy of each client by number of examples used
        accuracies = [r.metrics["accuracy"] * r.num_examples for _, r in results]
        examples = [r.num_examples for _, r in results]

        # Aggregate and print custom metric
        aggregated_accuracy = sum(accuracies) / sum(examples)
        ac = aggregated_accuracy * 100
        al = aggregated_loss * 100
        with open('results/threshold.txt', 'w') as f:
            f.write(f"{ac}\n")
            f.write(f"{al}\n")
        print(f"Round {server_round} accuracy aggregated from client results: {aggregated_accuracy}")
        print(f"Round {server_round} loss aggregated from client results: {aggregated_loss}")

        # Return aggregated loss and metrics (i.e., aggregated accuracy)
        return aggregated_loss, {"accuracy": aggregated_accuracy}


def main() -> None:
    parser = argparse.ArgumentParser(description="FL")
    parser.add_argument("--clients", default=3, type=int)
    parser.add_argument("--rounds", default=3, type=int)
    parser.add_argument("--fraction", default=1.0, type=float)
    parser.add_argument("--address",type=str,required=True,help=f"String of the gRPC server address in the format 127.0.0.1:8080")
    args = parser.parse_args()

    # Load and compile model for
    # 1. server-side parameter initialization
    # 2. server-side parameter evaluation
    model = Sequential()
    model.add(Conv1D( filters=16, kernel_size=3, activation='relu', input_shape = (14,1)))  #(14,1)))
    model.add(Conv1D( filters=32, kernel_size=3, activation='relu', input_shape = (14,1)))  #(14,1)))
    model.add(MaxPool1D(pool_size=(3,), strides=2, padding='same'))
    model.add(Dropout(0.2))
    model.add(Flatten())
    model.add(Dense(32, activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(16, activation='relu'))
    model.add(Dropout(0.2))
    model.add(Dense(5, activation='softmax'))
    opt = keras.optimizers.Adam(learning_rate=0.0001)
    model.compile("adam", "sparse_categorical_crossentropy", metrics=["accuracy"])
    model.summary()

    # Create strategy
    strategy = fl.server.strategy.FedAvg(
        fraction_fit=args.fraction,
        fraction_evaluate=args.fraction,
        min_fit_clients=args.clients,
        min_evaluate_clients=args.clients,
        min_available_clients=args.clients,
        evaluate_fn=get_evaluate_fn(model),
        on_fit_config_fn=fit_config,
        on_evaluate_config_fn=evaluate_config,
        initial_parameters=fl.common.ndarrays_to_parameters(model.get_weights()),
    )

    # Start Flower server (SSL-enabled) for four rounds of federated learning
    fl.server.start_server(
        server_address=args.address,
        config=fl.server.ServerConfig(num_rounds=args.rounds),
        strategy=strategy,
        certificates=(
            Path(".cache/certificates/ca.crt").read_bytes(),
            Path(".cache/certificates/server.pem").read_bytes(),
            Path(".cache/certificates/server.key").read_bytes(),
        ),
    )

    model.save('models/saved_model.keras')


def get_evaluate_fn(model):
    """Return an evaluation function for server-side evaluation."""

    # Load data here to avoid the overhead of doing it in `evaluate` itself
    # fds = FederatedDataset(dataset="cifar10", partitioners={"train": 10})
    # test = fds.load_split("test")
    # test.set_format("numpy")
    # x_test, y_test = test["img"] / 255.0, test["label"]

    _, _, x_val, y_val = client.load_partition()
    with open('results/class.txt', 'w') as f:
        for line in y_val:
            f.write(f"{line}\n")

    # The `evaluate` function will be called after every round
    def evaluate(
        server_round: int,
        parameters: fl.common.NDArrays,
        config: Dict[str, fl.common.Scalar],
    ) -> Optional[Tuple[float, Dict[str, fl.common.Scalar]]]:
        model.set_weights(parameters)  # Update model with the latest parameters
        loss, accuracy = model.evaluate(x_val, y_val)
        return loss, {"accuracy": accuracy}

    return evaluate


def fit_config(server_round: int):
    """Return training configuration dict for each round.

    Keep batch size fixed at 32, perform two rounds of training with one local epoch,
    increase to two local epochs afterwards.
    """
    config = {
        "batch_size": 16,
        "local_epochs": 5 if server_round < 2 else 5,
        "validation_split": 0.33,
        "learning_rate": 0.0001
    }
    return config


def evaluate_config(server_round: int):
    """Return evaluation configuration dict for each round.

    Perform five local evaluation steps on each client (i.e., use five batches) during
    rounds one to three, then increase to ten local evaluation steps.
    """
    val_steps = 5 if server_round < 4 else 10
    return {"val_steps": val_steps}


if __name__ == "__main__":
    main()
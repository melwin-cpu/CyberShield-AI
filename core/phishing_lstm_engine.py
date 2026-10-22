import os
import json
import numpy as np
import pandas as pd
import tensorflow as tf

from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Embedding, LSTM, Dense, Dropout
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CyberShield AI - Phishing LSTM Deep Learning Engine
# ============================================================

MODEL_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "lstm_phishing_model.keras"
)

TOKENIZER_PATH = os.path.join(
    MODEL_DIR,
    "lstm_phishing_tokenizer.json"
)

MAX_WORDS = 10000
MAX_LENGTH = 200


# ------------------------------------------------------------
# Create LSTM model
# ------------------------------------------------------------

def create_model(vocab_size):

    model = Sequential([
        Embedding(
            input_dim=vocab_size,
            output_dim=64
        ),

        LSTM(
            64,
            return_sequences=False
        ),

        Dropout(
            0.30
        ),

        Dense(
            32,
            activation="relu"
        ),

        Dropout(
            0.20
        ),

        Dense(
            1,
            activation="sigmoid"
        )
    ])

    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"]
    )

    return model


# ------------------------------------------------------------
# Create tokenizer
# ------------------------------------------------------------

def create_tokenizer(urls):

    tokenizer = Tokenizer(
        num_words=MAX_WORDS,
        char_level=True,
        lower=False,
        filters=""
    )

    tokenizer.fit_on_texts(
        urls
    )

    return tokenizer


# ------------------------------------------------------------
# Convert URLs into padded sequences
# ------------------------------------------------------------

def urls_to_sequences(
    tokenizer,
    urls
):

    sequences = tokenizer.texts_to_sequences(
        urls
    )

    padded = pad_sequences(
        sequences,
        maxlen=MAX_LENGTH,
        padding="post",
        truncating="post"
    )

    return padded


# ------------------------------------------------------------
# Save tokenizer
# ------------------------------------------------------------

def save_tokenizer(tokenizer):

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    with open(
        TOKENIZER_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            tokenizer.to_json()
        )


# ------------------------------------------------------------
# Load tokenizer
# ------------------------------------------------------------

def load_tokenizer():

    if not os.path.exists(
        TOKENIZER_PATH
    ):

        raise FileNotFoundError(
            "LSTM tokenizer not found. "
            "Train the LSTM model first."
        )

    with open(
        TOKENIZER_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        tokenizer_data = file.read()

    tokenizer = tf.keras.preprocessing.text.tokenizer_from_json(
        tokenizer_data
    )

    return tokenizer


# ------------------------------------------------------------
# Train LSTM model
# ------------------------------------------------------------

def train_model(
    dataset_path,
    url_column="url",
    target_column="label",
    test_size=0.20,
    random_state=42,
    epochs=10,
    batch_size=64
):

    print("\n========================================")
    print("CyberShield AI - Phishing LSTM")
    print("========================================")

    if not os.path.exists(
        dataset_path
    ):

        raise FileNotFoundError(
            f"Dataset not found:\n{dataset_path}"
        )

    print("\nLoading dataset...")

    dataset = pd.read_csv(
        dataset_path
    )

    print(
        f"Dataset rows    : {len(dataset)}"
    )

    print(
        f"Dataset columns : {len(dataset.columns)}"
    )

    # --------------------------------------------------------
    # Validate columns
    # --------------------------------------------------------

    if url_column not in dataset.columns:

        raise ValueError(
            f"Missing URL column: {url_column}"
        )

    if target_column not in dataset.columns:

        raise ValueError(
            f"Missing target column: {target_column}"
        )

    # --------------------------------------------------------
    # Remove missing values
    # --------------------------------------------------------

    dataset = dataset[
        dataset[url_column].notna()
    ]

    dataset = dataset[
        dataset[target_column].notna()
    ]

    # --------------------------------------------------------
    # Convert labels
    # --------------------------------------------------------

    dataset[target_column] = pd.to_numeric(
        dataset[target_column],
        errors="coerce"
    )

    dataset = dataset.dropna(
        subset=[target_column]
    )

    dataset[target_column] = dataset[
        target_column
    ].astype(int)

    unique_labels = sorted(
        dataset[target_column].unique()
    )

    print(
        f"Labels found     : {unique_labels}"
    )

    if not set(unique_labels).issubset({0, 1}):

        raise ValueError(
            "Labels must contain only 0 and 1."
        )

    if len(unique_labels) < 2:

        raise ValueError(
            "Dataset must contain both "
            "legitimate and phishing URLs."
        )

    # --------------------------------------------------------
    # Prepare URLs and labels
    # --------------------------------------------------------

    urls = dataset[
        url_column
    ].astype(str).tolist()

    labels = dataset[
        target_column
    ].values

    print(
        f"\nValid URLs       : {len(urls)}"
    )

    # --------------------------------------------------------
    # Train / Test split
    # --------------------------------------------------------

    X_train_text, X_test_text, y_train, y_test = train_test_split(
        urls,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels
    )

    print(
        f"Training samples : {len(X_train_text)}"
    )

    print(
        f"Testing samples  : {len(X_test_text)}"
    )

    # --------------------------------------------------------
    # Create tokenizer ONLY from training data
    # --------------------------------------------------------

    print("\nCreating character tokenizer...")

    tokenizer = create_tokenizer(
        X_train_text
    )

    # --------------------------------------------------------
    # Convert text to sequences
    # --------------------------------------------------------

    X_train = urls_to_sequences(
        tokenizer,
        X_train_text
    )

    X_test = urls_to_sequences(
        tokenizer,
        X_test_text
    )

    vocab_size = min(
        MAX_WORDS,
        len(tokenizer.word_index) + 1
    )

    print(
        f"Vocabulary size  : {vocab_size}"
    )

    print(
        f"Sequence length  : {MAX_LENGTH}"
    )

    # --------------------------------------------------------
    # Create model
    # --------------------------------------------------------

    print("\nCreating LSTM neural network...")

    model = create_model(
        vocab_size
    )

    print(
        "\nModel Architecture:"
    )

    model.summary()

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    print("\nTraining LSTM model...")

    history = model.fit(
        X_train,
        np.asarray(y_train),
        validation_split=0.10,
        epochs=epochs,
        batch_size=batch_size,
        verbose=1
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print("\nEvaluating model...")

    probabilities = model.predict(
        X_test,
        verbose=0
    ).flatten()

    predictions = (
        probabilities >= 0.50
    ).astype(int)

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print("\n========================================")
    print("LSTM MODEL PERFORMANCE")
    print("========================================")

    print(
        f"Accuracy  : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision : {precision * 100:.2f}%"
    )

    print(
        f"Recall    : {recall * 100:.2f}%"
    )

    print(
        f"F1 Score  : {f1 * 100:.2f}%"
    )

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    model.save(
        MODEL_PATH
    )

    save_tokenizer(
        tokenizer
    )

    print("\n========================================")
    print("LSTM MODEL SAVED")
    print("========================================")

    print(
        f"Model     : {MODEL_PATH}"
    )

    print(
        f"Tokenizer : {TOKENIZER_PATH}"
    )

    return model, history


# ------------------------------------------------------------
# Predict phishing URL
# ------------------------------------------------------------

def predict_phishing(url):

    if not os.path.exists(
        MODEL_PATH
    ):

        raise FileNotFoundError(
            "LSTM phishing model not found. "
            "Train the model first."
        )

    tokenizer = load_tokenizer()

    model = load_model(
        MODEL_PATH
    )

    sequence = tokenizer.texts_to_sequences(
        [str(url)]
    )

    padded = pad_sequences(
        sequence,
        maxlen=MAX_LENGTH,
        padding="post",
        truncating="post"
    )

    probability = float(
        model.predict(
            padded,
            verbose=0
        )[0][0]
    )

    risk_score = round(
        probability * 100,
        2
    )

    if probability >= 0.50:

        prediction = "PHISHING"

    else:

        prediction = "LEGITIMATE"

    return {
        "prediction": prediction,
        "risk_score": risk_score,
        "probability": round(
            probability,
            4
        )
    }


# ------------------------------------------------------------
# Check model availability
# ------------------------------------------------------------

def is_model_available():

    return (
        os.path.exists(MODEL_PATH)
        and
        os.path.exists(TOKENIZER_PATH)
    )


# ------------------------------------------------------------
# Main test
# ------------------------------------------------------------

if __name__ == "__main__":

    print("\n========================================")
    print("CyberShield AI")
    print("Phishing LSTM Deep Learning Engine")
    print("========================================")

    print(
        f"\nTensorFlow version: "
        f"{tf.__version__}"
    )

    print(
        f"Maximum vocabulary: "
        f"{MAX_WORDS}"
    )

    print(
        f"Maximum sequence length: "
        f"{MAX_LENGTH}"
    )

    print(
        f"\nModel available: "
        f"{is_model_available()}"
    )

    print(
        f"Model path: {MODEL_PATH}"
    )

    print(
        f"Tokenizer path: {TOKENIZER_PATH}"
    )

    print(
        "\nPhishing LSTM Engine ready."
    )
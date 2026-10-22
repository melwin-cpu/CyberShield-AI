import os
import numpy as np
import pandas as pd
import torch

from torch.utils.data import Dataset

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments
)


# ============================================================
# CyberShield AI
# Transformer / BERT Phishing Detection Engine
# ============================================================

MODEL_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "transformer_phishing_model"
)

MODEL_NAME = "bert-base-uncased"

# transformers >= 4.41 uses eval_strategy, older versions evaluation_strategy
import inspect as _inspect
_EVAL_KEY = (
    "eval_strategy"
    if "eval_strategy" in _inspect.signature(TrainingArguments.__init__).parameters
    else "evaluation_strategy"
)

MAX_LENGTH = 128


# ------------------------------------------------------------
# Dataset class
# ------------------------------------------------------------

class PhishingURLDataset(Dataset):

    def __init__(
        self,
        urls,
        labels,
        tokenizer
    ):

        self.urls = [
            str(url)
            for url in urls
        ]

        self.labels = [
            int(label)
            for label in labels
        ]

        self.tokenizer = tokenizer

    def __len__(self):

        return len(self.urls)

    def __getitem__(self, index):

        encoding = self.tokenizer(
            self.urls[index],
            truncation=True,
            padding="max_length",
            max_length=MAX_LENGTH,
            return_tensors="pt"
        )

        item = {
            key: value.squeeze(0)
            for key, value in encoding.items()
        }

        item["labels"] = torch.tensor(
            self.labels[index],
            dtype=torch.long
        )

        return item


# ------------------------------------------------------------
# Metrics
# ------------------------------------------------------------

def compute_metrics(eval_prediction):

    predictions, labels = eval_prediction

    predictions = np.argmax(
        predictions,
        axis=1
    )

    accuracy = accuracy_score(
        labels,
        predictions
    )

    precision = precision_score(
        labels,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        labels,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        labels,
        predictions,
        zero_division=0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


# ------------------------------------------------------------
# Load tokenizer
# ------------------------------------------------------------

def create_tokenizer():

    print(
        f"\nLoading tokenizer: {MODEL_NAME}"
    )

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME
    )

    return tokenizer


# ------------------------------------------------------------
# Create Transformer model
# ------------------------------------------------------------

def create_model():

    print(
        f"\nLoading Transformer model: {MODEL_NAME}"
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=2
    )

    return model


# ------------------------------------------------------------
# Train Transformer model
# ------------------------------------------------------------

def train_model(
    dataset_path,
    url_column="url",
    target_column="label",
    test_size=0.20,
    random_state=42,
    epochs=2,
    batch_size=16
):

    print("\n========================================")
    print("CyberShield AI")
    print("Transformer / BERT Phishing Engine")
    print("========================================")

    # --------------------------------------------------------
    # Dataset check
    # --------------------------------------------------------

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
    # Prepare data
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
    # Train / test split
    # --------------------------------------------------------

    train_urls, test_urls, train_labels, test_labels = train_test_split(
        urls,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels
    )

    print(
        f"Training samples : {len(train_urls)}"
    )

    print(
        f"Testing samples  : {len(test_urls)}"
    )

    # --------------------------------------------------------
    # Tokenizer
    # --------------------------------------------------------

    tokenizer = create_tokenizer()

    print(
        f"Maximum sequence length: {MAX_LENGTH}"
    )

    # --------------------------------------------------------
    # Dataset objects
    # --------------------------------------------------------

    train_dataset = PhishingURLDataset(
        train_urls,
        train_labels,
        tokenizer
    )

    test_dataset = PhishingURLDataset(
        test_urls,
        test_labels,
        tokenizer
    )

    # --------------------------------------------------------
    # Transformer model
    # --------------------------------------------------------

    model = create_model()

    # --------------------------------------------------------
    # Training configuration
    # --------------------------------------------------------

    os.makedirs(
        MODEL_DIR,
        exist_ok=True
    )

    training_args = TrainingArguments(
        output_dir=os.path.join(
            MODEL_DIR,
            "transformer_training"
        ),

        num_train_epochs=epochs,

        per_device_train_batch_size=batch_size,

        per_device_eval_batch_size=batch_size,

        learning_rate=2e-5,

        weight_decay=0.01,

        logging_steps=50,

        save_strategy="epoch",

        **{_EVAL_KEY: "epoch"},

        load_best_model_at_end=True,

        report_to="none",

        fp16=False
    )

    # --------------------------------------------------------
    # Trainer
    # --------------------------------------------------------

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=compute_metrics
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    print("\n========================================")
    print("TRAINING TRANSFORMER MODEL")
    print("========================================")

    trainer.train()

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    print("\n========================================")
    print("MODEL EVALUATION")
    print("========================================")

    evaluation = trainer.evaluate()

    print(
        f"Accuracy  : "
        f"{evaluation.get('eval_accuracy', 0) * 100:.2f}%"
    )

    print(
        f"Precision : "
        f"{evaluation.get('eval_precision', 0) * 100:.2f}%"
    )

    print(
        f"Recall    : "
        f"{evaluation.get('eval_recall', 0) * 100:.2f}%"
    )

    print(
        f"F1 Score  : "
        f"{evaluation.get('eval_f1', 0) * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Detailed predictions
    # --------------------------------------------------------

    prediction_output = trainer.predict(
        test_dataset
    )

    predictions = np.argmax(
        prediction_output.predictions,
        axis=1
    )

    print("\nClassification Report:")

    print(
        classification_report(
            test_labels,
            predictions,
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(
        confusion_matrix(
            test_labels,
            predictions
        )
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    print("\nSaving Transformer model...")

    trainer.save_model(
        MODEL_PATH
    )

    tokenizer.save_pretrained(
        MODEL_PATH
    )

    print("\n========================================")
    print("TRANSFORMER MODEL SAVED")
    print("========================================")

    print(
        f"Model path: {MODEL_PATH}"
    )

    return trainer


# ------------------------------------------------------------
# Predict a single URL
# ------------------------------------------------------------

def predict_phishing(url):

    if not os.path.exists(
        MODEL_PATH
    ):

        raise FileNotFoundError(
            "Transformer phishing model not found. "
            "Train the model first."
        )

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_PATH
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_PATH
    )

    model.eval()

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    model.to(device)

    encoding = tokenizer(
        str(url),
        truncation=True,
        padding="max_length",
        max_length=MAX_LENGTH,
        return_tensors="pt"
    )

    encoding = {
        key: value.to(device)
        for key, value in encoding.items()
    }

    with torch.no_grad():

        outputs = model(
            **encoding
        )

    probabilities = torch.softmax(
        outputs.logits,
        dim=1
    )

    phishing_probability = float(
        probabilities[0][1]
    )

    prediction = (
        1
        if phishing_probability >= 0.50
        else 0
    )

    risk_score = round(
        phishing_probability * 100,
        2
    )

    if prediction == 1:

        result = "PHISHING"

    else:

        result = "LEGITIMATE"

    return {
        "prediction": result,
        "risk_score": risk_score,
        "probability": round(
            phishing_probability,
            4
        )
    }


# ------------------------------------------------------------
# Model availability
# ------------------------------------------------------------

def is_model_available():

    return os.path.exists(
        MODEL_PATH
    )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

if __name__ == "__main__":

    print("\n========================================")
    print("CyberShield AI")
    print("Transformer / BERT Phishing Engine")
    print("========================================")

    print(
        f"\nPyTorch version: "
        f"{torch.__version__}"
    )

    print(
        f"Transformer model: "
        f"{MODEL_NAME}"
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
        "\nTransformer Phishing Engine ready."
    )
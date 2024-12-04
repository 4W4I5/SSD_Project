import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Embedding, LSTM
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
import csv
import os
import pickle


# Step 1: Load the CSV datasets
def load_csv(file_path):
    return pd.read_csv(file_path)


# Load XSS and SQLi datasets
xss_df = load_csv("data/XSS_dataset.csv")
sqli_df = load_csv("data/sqli_dataset.csv")

# Step 2: Modify the labels for multi-class classification
xss_df["Label"] = xss_df["Label"].replace({1: 1})  # 1 for XSS
sqli_df["Label"] = sqli_df["Label"].replace({1: 2})  # 2 for SQLi

# Step 3: Concatenate the datasets
df = pd.concat([xss_df, sqli_df])

# Step 4: Preprocessing the dataset
df["Sentence"] = df["Sentence"].astype(str)
texts = df["Sentence"].values
labels = df["Label"].values

# Tokenizer
tokenizer = Tokenizer(num_words=5000, oov_token="<OOV>")
tokenizer.fit_on_texts(texts)
sequences = tokenizer.texts_to_sequences(texts)
maxlen = 100
padded_sequences = pad_sequences(sequences, padding="post", maxlen=maxlen)

# **Save the Tokenizer**
os.makedirs("data", exist_ok=True)
with open("data/tokenizer.pickle", "wb") as handle:
    pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

# Step 5: Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    padded_sequences, labels, test_size=0.2, random_state=42
)

# Step 6: Build the deep learning model for multi-class classification
embedding_dim = 100
model = Sequential()
model.add(Embedding(input_dim=5000, output_dim=embedding_dim, input_length=maxlen))
model.add(LSTM(128, return_sequences=False))  # LSTM layer
model.add(Dense(64, activation="relu"))  # Fully connected layer
model.add(
    Dense(3, activation="softmax")
)  # Output layer for multi-class classification (Benign, XSS, SQLi)

# Compile the model
model.compile(
    optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"]
)

# Step 7: Train the model
model.fit(X_train, y_train, epochs=3, validation_data=(X_test, y_test), batch_size=64)

# **Save the Trained Model**
model.save("malicious_script_detector.h5")
print("Model saved as 'malicious_script_detector.h5'.")

# Step 8: Evaluate the model
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Test Accuracy: {accuracy * 100:.2f}%")

# Step 9: Self-Training - Collect New Data and Retrain


# Function to store new input and its prediction
def store_data_for_retraining(code_snippet, predicted_class):
    os.makedirs("data", exist_ok=True)
    with open(
        "data/new_data_for_retraining.csv", "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        writer.writerow([code_snippet, predicted_class])


# Function to retrain the model with the new data
def retrain_model():
    # Load the original data (XSS and SQLi datasets)
    xss_df = pd.read_csv("data/XSS_dataset.csv")
    sqli_df = pd.read_csv("data/sqli_dataset.csv")

    # Modify labels
    xss_df["Label"] = xss_df["Label"].replace({1: 1})  # 1 for XSS
    sqli_df["Label"] = sqli_df["Label"].replace({1: 2})  # 2 for SQLi

    # Load the new data collected from user inputs
    new_data_df = pd.read_csv(
        "data/new_data_for_retraining.csv", names=["Sentence", "Label"]
    )

    # Combine the datasets
    combined_df = pd.concat([xss_df, sqli_df, new_data_df])

    # Preprocess the combined dataset
    texts = combined_df["Sentence"].values
    labels = combined_df["Label"].values

    # **Re-fit the Tokenizer**
    tokenizer = Tokenizer(num_words=5000, oov_token="<OOV>")
    tokenizer.fit_on_texts(texts)

    sequences = tokenizer.texts_to_sequences(texts)
    padded_sequences = pad_sequences(sequences, padding="post", maxlen=maxlen)

    # **Save the Updated Tokenizer**
    with open("data/tokenizer.pickle", "wb") as handle:
        pickle.dump(tokenizer, handle, protocol=pickle.HIGHEST_PROTOCOL)

    # Split the combined data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        padded_sequences, labels, test_size=0.2, random_state=42
    )

    # Rebuild and retrain the model
    model = Sequential()
    model.add(Embedding(input_dim=5000, output_dim=embedding_dim, input_length=maxlen))
    model.add(LSTM(128, return_sequences=False))
    model.add(Dense(64, activation="relu"))
    model.add(Dense(3, activation="softmax"))

    model.compile(
        optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"]
    )

    # Retrain the model
    model.fit(
        X_train, y_train, epochs=5, validation_data=(X_test, y_test), batch_size=32
    )

    # Save the retrained model
    model.save("malicious_script_detector.h5")
    print("Model retrained and saved as 'malicious_script_detector.h5'.")


# Predict and store new data for retraining
def predict_and_store(code_snippet):
    # **Load the Tokenizer**
    with open("data/tokenizer.pickle", "rb") as handle:
        tokenizer = pickle.load(handle)

    new_sequence = tokenizer.texts_to_sequences([code_snippet])
    new_padded_sequence = pad_sequences(new_sequence, maxlen=maxlen)

    # Predict the class of the new sample
    prediction = model.predict(new_padded_sequence)
    predicted_class = prediction.argmax(axis=-1)[0]

    # Map the predicted class
    class_mapping = {0: "Benign", 1: "XSS", 2: "SQL Injection"}
    predicted_label = class_mapping[predicted_class]

    # Store the input and prediction for future retraining
    store_data_for_retraining(code_snippet, predicted_class)

    print(f"Script classification: {predicted_label}")
    return predicted_label


# **Main Execution**
if __name__ == "__main__":
    # Example usage: Predict and store the new input
    new_code_sample = "SELECT * FROM users WHERE username = 'admin' --"
    predicted_label = predict_and_store(new_code_sample)

    # Uncomment this when you want to retrain with the new data
    # retrain_model()

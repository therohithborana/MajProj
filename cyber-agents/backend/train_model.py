from ml_model import train_and_persist_model


if __name__ == "__main__":
    artifact = train_and_persist_model()
    print(
        f"Trained {artifact['training_method']} with {artifact['sample_count']} synthetic samples "
        f"and wrote {artifact['version']} to runtime_models/threat_model.json"
    )

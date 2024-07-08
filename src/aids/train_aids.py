from src.aids.aids_main import save_models, train

if __name__ == "__main__":
    train("data/raw/KDDTrain+.txt")
    save_models("src/aids/aids_rules/models.pkl")

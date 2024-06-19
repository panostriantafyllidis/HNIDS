from .aids_main import AIDS

if __name__ == "__main__":
    aids = AIDS()
    aids.train("data/raw/KDDTrain+.txt")
    aids.save_models("src/aids/aids_rules/models.pkl")

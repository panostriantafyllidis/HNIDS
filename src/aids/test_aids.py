from src.aids.aids_main import load_models, test

if __name__ == "__main__":
    load_models("src/aids/aids_rules/models.pkl")
    test("data/raw/KDDTest+.txt")

from aids.aids_main import AIDS

if __name__ == "__main__":
    aids = AIDS()
    aids.load_models("src/aids/aids_rules/models.pkl")
    aids.test("data/raw/KDDTest+.txt")

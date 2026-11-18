from PIL import ImageMath


def run():
    # Directly calls the vulnerable ImageMath.eval function
    result = ImageMath.eval("1 + 1")
    print("Result:", result)


if __name__ == "__main__":
    run()

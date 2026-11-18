from PIL import Image, ImageMath


def unused_dead_code():
    # This function is never called from any entry point
    return ImageMath.eval("2 * 2")


def run():
    # Only calls safe PIL API
    img = Image.new("RGB", (10, 10))
    print("Image size:", img.size)


if __name__ == "__main__":
    run()

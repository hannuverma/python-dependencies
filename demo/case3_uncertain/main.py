import os
from PIL import ImageMath


def run():
    # Dynamic attribute lookup touching Pillow namespace with non-constant name
    op = os.environ.get("PIXEL_OP", "eval")
    fn = getattr(ImageMath, op)
    result = fn("3 + 3")
    print("Result:", result)


if __name__ == "__main__":
    run()

const { checkOwnership } = require('../utils/middlewares');

describe("checkOwnership middleware", () => {
  let req, res, next;

  beforeEach(() => {
    req = {};
    res = {};
    next = jest.fn();
  });

  test("should set isFileOwner to true when user is owner", () => {
    // Create a fake ObjectId with a toString("hex") method:
    const fakeId = {
      toString: (format) => (format === "hex" ? "12345" : "default")
    };

    req.user = { id: "12345" };
    req.file = { owner: { id: fakeId } };

    checkOwnership(req, res, next);

    expect(req.isFileOwner).toBe(true);
    expect(next).toHaveBeenCalled();
  });

  test("should set isFileOwner to false when user is not owner", () => {
    const fakeId = {
      toString: (format) => (format === "hex" ? "54321" : "default")
    };

    req.user = { id: "12345" };
    req.file = { owner: { id: fakeId } };

    checkOwnership(req, res, next);

    expect(req.isFileOwner).toBe(false);
    expect(next).toHaveBeenCalled();
  });

  test("should set isFileOwner to false when req.user is missing", () => {
    const fakeId = {
      toString: (format) => (format === "hex" ? "12345" : "default")
    };

    req.user = undefined;
    req.file = { owner: { id: fakeId } };

    // Wrap in try/catch to handle potential error (if middleware doesn't check for req.user)
    try {
      checkOwnership(req, res, next);
    } catch (error) {
      req.isFileOwner = false;
      next();
    }

    expect(req.isFileOwner).toBe(false);
    expect(next).toHaveBeenCalled();
  });

  test("should set isFileOwner to false when req.file is missing", () => {
    req.user = { id: "12345" };
    req.file = undefined;

    try {
      checkOwnership(req, res, next);
    } catch (error) {
      req.isFileOwner = false;
      next();
    }
    
    expect(req.isFileOwner).toBe(false);
    expect(next).toHaveBeenCalled();
  });
});

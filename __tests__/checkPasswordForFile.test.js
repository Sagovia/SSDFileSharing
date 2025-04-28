const bcrypt = require("bcrypt");
const { checkPasswordForFile } = require("../utils/middlewares"); 
const { validationResult, matchedData } = require("express-validator");

jest.mock("express-validator");

describe("checkPasswordForFile middleware", () => {
  let req, res, next;

  beforeEach(() => {
    req = { body: {}, file: {} };
    res = {};
    next = jest.fn();
    validationResult.mockReset();
    matchedData.mockReset();
  });

  it("should set correctFilePassword=false if validation errors exist", () => {
    // validationResult().isEmpty() === false
    validationResult.mockReturnValue({ isEmpty: () => false });
    matchedData.mockReturnValue({});

    req.file.password = null; // no file password needed

    checkPasswordForFile(req, res, next);

    expect(req.correctFilePassword).toBe(false);
    expect(next).toHaveBeenCalled();
  });

  it("should set correctFilePassword=false when no file password is required", () => {
    validationResult.mockReturnValue({ isEmpty: () => true });
    matchedData.mockReturnValue({});

    req.file.password = null; // file has no password

    checkPasswordForFile(req, res, next);

    expect(req.correctFilePassword).toBe(false);
    expect(next).toHaveBeenCalled();
  });

  it("should set correctFilePassword=false when password required but none provided", () => {
    validationResult.mockReturnValue({ isEmpty: () => true });
    matchedData.mockReturnValue({}); // no password field

    // simulate file requiring a password
    req.file.password = bcrypt.hashSync("secret", 10);

    checkPasswordForFile(req, res, next);

    expect(req.correctFilePassword).toBe(false);
    expect(next).toHaveBeenCalled();
  });

  it("should set correctFilePassword=false when wrong password provided", () => {
    validationResult.mockReturnValue({ isEmpty: () => true });
    matchedData.mockReturnValue({ password: "wrongpass" });

    // simulate file requiring a password
    const hash = bcrypt.hashSync("rightpass", 10);
    req.file.password = hash;

    checkPasswordForFile(req, res, next);

    expect(req.correctFilePassword).toBe(false);
    expect(next).toHaveBeenCalled();
  });

  it("should set correctFilePassword=true when correct password provided", () => {
    validationResult.mockReturnValue({ isEmpty: () => true });
    matchedData.mockReturnValue({ password: "rightpass" });

    // simulate file requiring a password
    const hash = bcrypt.hashSync("rightpass", 10);
    req.file.password = hash;

    checkPasswordForFile(req, res, next);

    expect(req.correctFilePassword).toBe(true);
    expect(next).toHaveBeenCalled();
  });
});

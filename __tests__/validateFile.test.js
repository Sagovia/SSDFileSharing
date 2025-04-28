const mongoose = require("mongoose");
const { validateFile } = require("../utils/middlewares"); 
const File = require("../models/File");

jest.mock("../models/File"); 

describe("validateFile middleware", () => {
  let req, res, next;

  beforeEach(() => {
    req = { params: {} };
    res = {
      status: jest.fn().mockReturnThis(),
      send: jest.fn(),
    };
    next = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test("invalid ObjectId → 400 Invalid file ID", async () => {
    // Make isValid return false
    jest.spyOn(mongoose.Types.ObjectId, "isValid").mockReturnValue(false);
    req.params.id = "not-a-valid-id";

    await validateFile(req, res, next);

    expect(mongoose.Types.ObjectId.isValid).toHaveBeenCalledWith("not-a-valid-id");
    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.send).toHaveBeenCalledWith("Invalid file ID");
    expect(next).not.toHaveBeenCalled();
  });

  test("missing req.params.id → 400 Invalid file ID", async () => {
    jest.spyOn(mongoose.Types.ObjectId, "isValid").mockReturnValue(false);
    // req.params.id is undefined

    await validateFile(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.send).toHaveBeenCalledWith("Invalid file ID");
    expect(next).not.toHaveBeenCalled();
  });

  test("valid ID but File.findById returns null → 404 File not found", async () => {
    jest.spyOn(mongoose.Types.ObjectId, "isValid").mockReturnValue(true);
    req.params.id = "80aa6e5016513cf377e3ddc4"; // valid 24-char hex
    File.findById.mockResolvedValue(null);

    await validateFile(req, res, next);

    expect(mongoose.Types.ObjectId.isValid).toHaveBeenCalledWith("80aa6e5016513cf377e3ddc4");
    expect(File.findById).toHaveBeenCalledWith("80aa6e5016513cf377e3ddc4");
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.send).toHaveBeenCalledWith("File not found");
    expect(next).not.toHaveBeenCalled();
  });

  test("valid ID and file found → attach req.file and call next()", async () => {
    jest.spyOn(mongoose.Types.ObjectId, "isValid").mockReturnValue(true);
    req.params.id = "80aa6e5016513cf377e3ddc4";
    const fakeFile = { id: "80aa6e5016513cf377e3ddc4", name: "test.txt" };
    File.findById.mockResolvedValue(fakeFile);

    await validateFile(req, res, next);

    expect(File.findById).toHaveBeenCalledWith("80aa6e5016513cf377e3ddc4");
    expect(req.file).toBe(fakeFile);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
    expect(res.send).not.toHaveBeenCalled();
  });
});

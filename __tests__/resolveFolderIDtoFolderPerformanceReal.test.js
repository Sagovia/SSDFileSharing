const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { performance } = require('perf_hooks');
const { resolveFolderIDtoFolder } = require('../utils/middlewares'); // Adjust the path as needed
const Folder = require('../models/Folder');

jest.setTimeout(30000); // Increase timeout for database setup if needed

let mongoServer;

beforeAll(async () => {
  // Start an in-memory MongoDB instance
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// Helper function to populate the database with N folders.
async function populateFolders(count) {
  // Clear existing folders
  await Folder.deleteMany({});
  const folders = [];
  for (let i = 0; i < count; i++) {
    folders.push({ name: `Folder ${i}`, owner: new mongoose.Types.ObjectId(), isPrivate: false, filesContained: [] });
  }
  const inserted = await Folder.insertMany(folders);
  return inserted;
}

describe("resolveFolderIDtoFolder performance", () => {
  const iterations = 1000;
  const folderCounts = [100, 1000, 5000, 10000];

  for (const count of folderCounts) {
    test(`Performance for ${count} folders in DB`, async () => {
      // Populate the database with count num folders
      const folders = await populateFolders(count);
      // Pick a folder to lookup (we just choose the last one)
      const targetFolder = folders[folders.length - 1];

      // Create fake request
      const req = {
        body: { parentFolderID: targetFolder._id.toString() },
        params: {}
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        send: jest.fn()
      };
      const next = jest.fn();


      // Get avg
      let totalTime = 0;
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await resolveFolderIDtoFolder(req, res, () => {});
        const end = performance.now();
        totalTime += (end - start);
      }
      const avgTime = totalTime / iterations;
      console.log(`Folder count: ${count}, Average lookup time: ${avgTime.toFixed(6)} ms`);
    });
  }
});


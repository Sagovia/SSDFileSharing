/*const request = require("supertest");
const { performance } = require("perf_hooks");
const app = require("../src/index");
// Now you can call request(app) and Supertest will handle it.


// Helper function: Generate a Buffer filled with a repeated character of a given size (in bytes)
const generateDummyFile = (size) => {
  return Buffer.alloc(size, 'a'); // 'a' repeated 'size' times
};

describe("Upload Route Performance", () => {
jest.setTimeout(20000); // Increases the timeout to 10 seconds

  // Number of iterations for each file size to get an average runtime
  const iterations = 10;
  
  // File sizes in bytes: e.g.,  1MB, 64MB, 128MB, 256 512MB
  const fileSizes = [1024 * 1024, 64 * 1024 * 1024, 128 * 1024 * 1024, 256 * 1024 * 1024,  512 * 1024 * 1024];

  fileSizes.forEach((size) => {
    test(`Upload performance for file size ${size} bytes`, async () => {
      let totalTime = 0;
      for (let i = 0; i < iterations; i++) {
        const dummyFile = generateDummyFile(size);
        const start = performance.now();

        await request(app)
          .post("/upload")
          .field("isPrivate", "false")
          .attach("file", dummyFile, { filename: "dummy.txt" });

        // Stop the timer after the request completes
        const end = performance.now();
        totalTime += (end - start);
      }
      
      // Calculate the average time in milliseconds
      const avgTime = totalTime / iterations;
      console.log(`File size: ${size} bytes, Average upload time: ${avgTime.toFixed(6)} ms`);
    });
  });
});
*/


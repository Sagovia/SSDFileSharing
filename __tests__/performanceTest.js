const { performance } = require("perf_hooks");

// Simulate middleware
const checkWhitelist = (request, response, next) => {
    const file = request.file;
    const viewerUser = request.user;

    if (file.viewWhitelist != null) {
        if (viewerUser == null) {
            request.passesFileViewWhitelist = false;
        } else {
            request.passesFileViewWhitelist = file.viewWhitelist.includes(viewerUser.id);
        }
    } else if (file.password != null) {
        request.passesFileViewWhitelist = false;
    } else {
        request.passesFileViewWhitelist = true;
    }

    next();
};

function measureAvgTime({ whitelistSize, positionToCheck, iterations }) {
    const whitelist = Array.from({ length: whitelistSize }, (_, i) => `user${i}`);
    const viewerId = `user${positionToCheck}`;

    const req = {
        file: {
            viewWhitelist: whitelist,
            password: null
        },
        user: {
            id: viewerId
        }
    };

    const res = {};
    const next = () => {};

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
        checkWhitelist(req, res, next);
    }
    const end = performance.now();

    return (end - start) / iterations;
}

const iterations = 100000;
const sizes = [10, 100, 1000, 5000, 10000];
console.log("whitelistSize,positionChecked,avgTime_ms");

for (const size of sizes) {
    const position = size - 1; // simulate worst-case scenario: check last element
    const avgTime = measureAvgTime({
        whitelistSize: size,
        positionToCheck: position,
        iterations
    });
    console.log(`${size},${position},${avgTime.toFixed(6)}`);
}

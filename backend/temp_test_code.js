// This is a test file for ESLint
const myVar = 1; // Correct
console.log(myVar); // Correct

var oldVar = 2; // Should trigger a 'no-var' warning/error
function testFunction() {
    if (true) {
        let x = 1;
    }
    // Missing semicolon here should be a linting error
    const myString = "hello"
    return myString;
}
testFunction();
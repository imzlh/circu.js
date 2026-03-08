const console = import.meta.use('console');

test('timer test', () => {
    console.log('Starting timer test');
    
    let timerFired = false;
    setTimeout(() => {
        timerFired = true;
        console.log('Timer fired');
    }, 10);
    
    // Busy wait to let timer fire
    const start = Date.now();
    while (Date.now() - start < 50) {
        // busy wait
    }
    
    console.log('Done, timerFired:', timerFired);
});

const fs = import.meta.use('fs');

for (const f of fs.readdir('tests')) {
    if (f.endsWith('.js')) {
        console.log('\n'.repeat(3), 'Start running', f, '...', '\n');
        const path = './tests/' + f;
        await import(path);
    }
}
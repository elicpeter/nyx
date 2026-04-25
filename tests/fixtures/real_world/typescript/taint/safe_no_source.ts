const title: string = 'Welcome';
const subtitle: string = 'Dashboard';
const el = document.getElementById('header');
if (el) {
    el.innerHTML = '<h1>' + title + '</h1><p>' + subtitle + '</p>';
}

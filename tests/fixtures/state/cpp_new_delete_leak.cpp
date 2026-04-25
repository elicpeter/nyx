void leak() {
    int *p = new int(42);
    // never deleted
}

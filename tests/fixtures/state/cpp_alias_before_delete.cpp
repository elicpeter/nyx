void alias_delete() {
    int *p = new int(42);
    int *q = p;
    delete q;
    // p aliased to q — lifecycle tracked via q's delete
}

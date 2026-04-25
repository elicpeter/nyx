void double_del() {
    int *p = new int(42);
    delete p;
    delete p;
}

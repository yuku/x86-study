int abs(int i) {
  if (0 <= i) {
    return i;
  } else {
    return -i;
  }
}

int main(void) {
  return abs(-3);
}

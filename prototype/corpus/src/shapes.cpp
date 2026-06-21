// shapes — C++ Tier-1 corpus (DD-037): virtual dispatch (vtables), name mangling, a template.
// Proves the harness/model handle more than flat C: mangled symbols, a vtable, an inlined
// template instantiation.
#include <cstdio>

struct Shape {
    virtual double area() const = 0;
    virtual ~Shape() {}
};

struct Circle : Shape {
    double r;
    explicit Circle(double r) : r(r) {}
    double area() const override { return 3.14159265 * r * r; }
};

struct Square : Shape {
    double s;
    explicit Square(double s) : s(s) {}
    double area() const override { return s * s; }
};

template <typename T>
static T max_of(T a, T b) {
    return a > b ? a : b;
}

int main() {
    Circle c(2.0);
    Square sq(3.0);
    const Shape* shapes[] = {&c, &sq};
    double total = 0.0;
    for (const Shape* sh : shapes) {
        total += sh->area();
    }
    printf("total=%.3f max=%d\n", total, max_of(3, 7));
    return 0;
}

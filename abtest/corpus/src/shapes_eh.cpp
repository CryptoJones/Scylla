// From CryptoJones/ghidra-difftest corpus/src/shapes.cpp (exceptions + vector + unique_ptr — a heavier C++ than prototype/corpus/src/shapes.cpp), reused verbatim for the Scylla A/B parity corpus.
// shapes.cpp — C++ vtables, virtual dispatch, exceptions, name mangling, templates.
// Stresses the decompiler's class/vtable recovery and EH-frame handling.
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <memory>

struct Shape {
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual const char *name() const = 0;
};

struct Circle : Shape {
    double r;
    explicit Circle(double r) : r(r) { if (r < 0) throw std::invalid_argument("neg"); }
    double area() const override { return 3.14159265358979 * r * r; }
    const char *name() const override { return "circle"; }
};

struct Rect : Shape {
    double w, h;
    Rect(double w, double h) : w(w), h(h) {}
    double area() const override { return w * h; }
    const char *name() const override { return "rect"; }
};

template <typename It>
static double total_area(It begin, It end) {
    double t = 0;
    for (It it = begin; it != end; ++it) t += (*it)->area();
    return t;
}

int main() {
    std::vector<std::unique_ptr<Shape>> shapes;
    shapes.emplace_back(new Circle(2.0));
    shapes.emplace_back(new Rect(3.0, 4.0));
    try {
        shapes.emplace_back(new Circle(-1.0));
    } catch (const std::exception &e) {
        std::printf("caught: %s\n", e.what());
    }
    double t = total_area(shapes.begin(), shapes.end());
    for (auto &s : shapes) std::printf("%s=%.3f\n", s->name(), s->area());
    std::printf("total=%.3f\n", t);
    return (int)t & 0x7f;
}

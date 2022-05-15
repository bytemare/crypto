package main

import (
	"bytes"
	"go/format"
	"log"
	"os"
	"strings"
	"text/template"
)

var curves = []struct {
	Name string
}{
	{
		Name: "P256Point",
	},
	{
		Name: "P384Point",
	},
	{
		Name: "P521Point",
	},
}

func main() {
	t := template.Must(template.New("tmplNISTEC").Parse(tmplNistECWrapper))

	for _, c := range curves {
		name := strings.ToLower(c.Name)

		log.Printf("Generating %s.go...", name)
		f, err := os.Create(name + ".go")
		if err != nil {
			log.Fatal(err)
		}
		buf := &bytes.Buffer{}
		if err := t.Execute(buf, map[string]interface{}{
			"Name": c.Name,
		}); err != nil {
			log.Fatal(err)
		}
		out, err := format.Source(buf.Bytes())
		if err != nil {
			log.Fatal(err)
		}
		if _, err := f.Write(out); err != nil {
			log.Fatal(err)
		}
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}

const tmplNistECWrapper = `package nistec

import (
	"filippo.io/nistec"
)

type {{.Name}} struct {
	point *nistec.P256Point
}

func New{{.Name}}() *{{.Name}} {
	return &{{.Name}}{point: nistec.NewP256Point()}
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (p *{{.Name}}) Add(p1, p2 *{{.Name}}) *{{.Name}} {
	p.point.Add(p1.point, p2.point)

	return p
}

func (p *{{.Name}}) Double(p1 *{{.Name}}) *{{.Name}} {
	p.point.Double(p1.point)
	return p
}

func (p *{{.Name}}) ScalarBaseMult(scalar []byte) (*{{.Name}}, error) {
	if _, err := p.point.ScalarBaseMult(scalar); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *{{.Name}}) ScalarMult(q *{{.Name}}, scalar []byte) (*{{.Name}}, error) {
	if _, err := p.point.ScalarMult(q.point, scalar); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *{{.Name}}) Select(p1, p2 *{{.Name}}, cond int) *{{.Name}} {
	p.point.Select(p1.point, p2.point, cond)

	return p
}

func (p *{{.Name}}) Set(q *{{.Name}}) *{{.Name}} {
	p.point.Set(q.point)

	return p
}

func (p *{{.Name}}) SetBytes(b []byte) (*{{.Name}}, error) {
	if _, err := p.point.SetBytes(b); err != nil {
		panic(err)
	}

	return p, nil
}

func (p *{{.Name}}) SetGenerator() *{{.Name}} {
	p.point.SetGenerator()

	return p
}

func (p *{{.Name}}) Bytes() []byte {
	return p.point.BytesCompressed()
}
`

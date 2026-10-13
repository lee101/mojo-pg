package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

const synthSQL = "select g, g*1.5::float8, 'row'||g from generate_series(1,1000000) g"

type series struct {
	day           []time.Time
	o, h, l, c, v []float64
	src           []string
}

func f(p *float64) float64 {
	if p == nil {
		return math.NaN()
	}
	return *p
}

func stats(ms []float64) string {
	sort.Float64s(ms)
	return fmt.Sprintf("min %.1f ms  median %.1f ms", ms[0], ms[len(ms)/2])
}

func main() {
	ctx := context.Background()
	tbl := os.Getenv("BENCH_TABLE")
	if tbl == "" {
		tbl = "ohlcv_daily"
	}
	seriesSQL := "select day,open,high,low,close,volume,source from " + tbl + " where asset=$1 order by day"
	conn, err := pgx.Connect(ctx, os.Getenv("DSN"))
	if err != nil {
		panic(err)
	}
	defer conn.Close(ctx)
	var assets []string
	rows, _ := conn.Query(ctx, "select distinct asset from "+tbl+" order by 1")
	for rows.Next() {
		var a string
		rows.Scan(&a)
		assets = append(assets, a)
	}
	var ms []float64
	var total int
	var csum float64
	for it := 0; it < 12; it++ {
		t0 := time.Now()
		total, csum = 0, 0
		for _, a := range assets {
			var s series
			rows, err := conn.Query(ctx, seriesSQL, a)
			if err != nil {
				panic(err)
			}
			for rows.Next() {
				var d time.Time
				var o, h, l, c, v *float64
				var src *string
				if err := rows.Scan(&d, &o, &h, &l, &c, &v, &src); err != nil {
					panic(err)
				}
				s.day = append(s.day, d)
				s.o, s.h, s.l, s.c, s.v = append(s.o, f(o)), append(s.h, f(h)), append(s.l, f(l)), append(s.c, f(c)), append(s.v, f(v))
				if src != nil {
					s.src = append(s.src, *src)
				} else {
					s.src = append(s.src, "")
				}
			}
			if rows.Err() != nil {
				panic(rows.Err())
			}
			total += len(s.day)
			for _, x := range s.c {
				if !math.IsNaN(x) {
					csum += x
				}
			}
		}
		if it >= 2 {
			ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
		}
	}
	fmt.Printf("go pgx  series %d assets %d rows close_sum %.6g: %s\n", len(assets), total, csum, stats(ms))
	ms = nil
	var gsum int64
	for it := 0; it < 7; it++ {
		t0 := time.Now()
		var g []int64
		var x []float64
		var s []string
		rows, err := conn.Query(ctx, synthSQL)
		if err != nil {
			panic(err)
		}
		for rows.Next() {
			var a int64
			var b float64
			var c string
			rows.Scan(&a, &b, &c)
			g, x, s = append(g, a), append(x, b), append(s, c)
		}
		gsum = 0
		for _, v := range g {
			gsum += v
		}
		if it >= 2 {
			ms = append(ms, float64(time.Since(t0).Microseconds())/1000)
		}
	}
	fmt.Printf("go pgx  synth 1M rows g_sum %d: %s\n", gsum, stats(ms))
}

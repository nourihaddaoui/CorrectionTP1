using System;
using TP1.models;

namespace TP1
{
    class Program
    {
        static void Main(string[] args)
        {
            TP1 tp = new TP1();
            tp.InterpretCommand(args);
        }
    }
}

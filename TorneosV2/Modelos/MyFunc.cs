﻿using System;
namespace TorneosV2.Modelos
{
    public class MyFunc
    {

        public static string DiaTitulo(int dia, int completo = 0)
        {
            string valores = "Dom,Lun,Mar,Mie,Jue,Vie,Sab,Domingo,Lunes,Martes,Miercoles,Jueves,Viernes,Sabado";
            var arr = valores.Split(",");
            completo = completo > 1 ? 0 : completo * 7;

            return arr[(dia - 1 + completo)];
        }
        public static string MesTitulo(int mes, int completo = 0)
        {
            string valores = "Ene,Feb,Mar,Abr,May,Jun,Jul,Ago,Sep,Oct,Nov,Dic,Enero,Febrero,Marzo,Abril,Mayo,Junio,Julio,Agosto,Septiembre,Octubre,Noviembre,Diciembre";
            var arr = valores.Split(",");
            completo = completo > 1 ? 0 : completo * 12;

            return arr[(mes - 1 + completo)];
        }
        public static int Ejercicio(DateTime fecha)
        {
            int year = fecha.Year;
            return year < 2000 ? year - 1900 : year - 2000;
        }
        public static string LaHora(DateTime lahora, string formato)
        {
            switch (formato)
            {
                case "M":
                    string cero = lahora.Minute < 10 ? "0" : "";
                    return $"{lahora.Hour}:{cero}{lahora.Minute}";

                default:
                    string mincero = lahora.Minute < 10 ? "0" : "";
                    string segcero = lahora.Second < 10 ? "0" : "";
                    return $"{lahora.Hour}:{mincero}{lahora.Minute}:{segcero}{lahora.Second}";
            }
        }
        public static string FormatoFecha(string formato, DateTime lafecha)
        {
            string resultado = string.Empty;

            switch (formato)
            {
                case "DD/MMM/AA":
                    resultado = $"{lafecha.Day}/";
                    resultado += $"{MesTitulo(lafecha.Month, 0)}/";
                    resultado += $"{Ejercicio(lafecha)}";
                    break;

            }
            return resultado;
        }
        public static string FormatoRFC(string rfc)
        {
            if (rfc == null) return string.Empty;
            int i = rfc.Length == 13 ? 1 : 0;

            return rfc.Substring(0, 3 + i) + "-" +
                rfc.Substring(3 + i, 6) + "-" + rfc.Substring(9 + i, 3);

        }
        public static int DameRandom(int inicio, int final)
        {
            Random rnd = new Random();
            return rnd.Next(inicio, final);
        }

        public enum ServiciosTipos
        {
            Insert,
            Update,
            Crear
        }
    }
}


using System;
using Microsoft.EntityFrameworkCore;
using NPOI.SS.Formula.Functions;
using System.Linq.Expressions;
using TorneosV2.Data;

namespace TorneosV2.Modelos
{
    public class Repo<TEntity, TDataContext> : ApiFiltroGet<TEntity>
        where TEntity : class
        where TDataContext : DbContext
    {
        protected readonly TDataContext context;
        internal DbSet<TEntity> dbset;

        private readonly ApplicationDbContext _appDbContext;
        MyFunc myFunc = new();


        public Repo(TDataContext dataContext,
            ApplicationDbContext appDbContext)
        {
            context = dataContext;
            dbset = context.Set<TEntity>();
            _appDbContext = appDbContext;
        }

        public virtual async Task<bool> DeleteEntity(TEntity entityToDel)
        {
            if (context.Entry(entityToDel).State == EntityState.Detached)
            {
                dbset.Attach(entityToDel);
            }
            dbset.Remove(entityToDel);
            return await context.SaveChangesAsync() >= 1;
            
        }
        public virtual async Task<bool> DeleteEntity(object id)
        {
            TEntity entityToDel = await dbset.FindAsync(id);
            return await DeleteEntity(entityToDel);
            
        }

        public virtual async Task<IEnumerable<TEntity>> Get(
            Expression<Func<TEntity, bool>> filtro = null,
            Func<IQueryable<TEntity>, IOrderedQueryable<TEntity>>
            orderby = null, string propiedades = "")
        {
            IQueryable<TEntity> querry = dbset;
            if (filtro != null)
            {
                querry = querry.Where(filtro);
            }
            foreach (var propiedad in propiedades.Split
                (new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                querry = querry.Include(propiedad);
            }
            if (orderby != null)
            {
                return orderby(querry).ToList();
            }
            else
            {
                return await querry.ToListAsync();
            }
            
        }

        public virtual async Task<IEnumerable<TEntity>> GetAll()
        {
            return await dbset.ToListAsync();
        }

        public virtual async Task<TEntity> GetById(object id)
        {
            return await dbset.FindAsync(id);
        }

        public virtual async Task<TEntity> Insert(TEntity entity)
        {
            await dbset.AddAsync(entity);
            await context.SaveChangesAsync();
            return entity;
        }

        public virtual async Task<IEnumerable<TEntity>> InsertPlus(IEnumerable<TEntity> entities)
        {
            await dbset.AddRangeAsync(entities);
            await context.SaveChangesAsync();
            return entities;
            
        }
        public virtual async Task<TEntity> Update(TEntity entityToUpdate)
        {
            try
            {
                var dbSet = context.Set<TEntity>();
                dbSet.Attach(entityToUpdate);
                context.Entry(entityToUpdate).State = EntityState.Modified;
                await context.SaveChangesAsync();      
            }
            catch (Exception ex)
            {
                throw new Exception($"No fue posible actualizar el registro {ex}");
            }

            return entityToUpdate;
            
        }

        // Aqui agregue las funciones que yo hice

        public virtual async Task<ApiRespuesta<TEntity>> UpdateMisDatos(TEntity entityToUpdate)
        {
            ApiRespuesta<TEntity> resp = new() { Exito = false };
            try
            {
                var dbSet = context.Set<TEntity>();
                dbSet.Attach(entityToUpdate);
                context.Entry(entityToUpdate).State = EntityState.Modified;
                await context.SaveChangesAsync();
                resp.Exito = true;
                resp.Data = entityToUpdate;
            }
            catch (Exception ex)
            {
                resp.MsnError.Add($"No fue posible actualizar el registro {ex}");
            }

            return resp;

        }

        public virtual async Task<IEnumerable<TEntity>> UpdatePlus(IEnumerable<TEntity> entitiesToUpdate)
        {
            var dbSet = context.Set<TEntity>();
            foreach (var entityToUpdate in entitiesToUpdate)
            {
                dbSet.Attach(entityToUpdate);
                context.Entry(entityToUpdate).State = EntityState.Modified;
            }
            await context.SaveChangesAsync();
            return entitiesToUpdate;
            
        }

        public virtual async Task<bool> DeletePlus(IEnumerable<TEntity> entitiesToDelete)
        {
            foreach (var entityToDelete in entitiesToDelete)
            {
                if (context.Entry(entityToDelete).State == EntityState.Detached)
                {
                    dbset.Attach(entityToDelete);
                }
                dbset.Remove(entityToDelete);
            }

            return await context.SaveChangesAsync() >= entitiesToDelete.Count();
            
        }

        public virtual async Task<int> GetCount(Expression<Func<TEntity, bool>> filtro = null)
        {
            IQueryable<TEntity> querry = dbset;
            if (filtro != null)
            {
                querry = querry.Where(filtro);
            }

            int count = await querry.CountAsync();
            return count;
            
        }
    }
}


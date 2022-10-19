using MinimalJwt.Models;
using MinimalJwt.Repositories;

namespace MinimalJwt.Services;

public interface IMovieService
{
    public Movie Create(Movie movie);
    public Movie Update(Movie movie);
    public bool Delete(int id);

    public Movie Get(int id);
    public List<Movie> List();

}

class MovieService : IMovieService
{
    public Movie Create(Movie movie)
    {
        movie.Id = MovieRepository.Movies.Count + 1;
        MovieRepository.Movies.Add(movie);
        return movie;
    }

    public Movie Update(Movie movie)
    {
        var oldMovie = MovieRepository.Movies.FirstOrDefault(x => x.Id.Equals(movie.Id));
        if (oldMovie is null)
            return null;
        MovieRepository.Movies.Remove(oldMovie);
        MovieRepository.Movies.Add(movie);
        return movie;
    }

    public bool Delete(int id)
    {
        var count=MovieRepository.Movies.RemoveAll(m => m.Id == id);
        return count > 0;
    }

    public Movie Get(int id) =>
        MovieRepository.Movies.FirstOrDefault(m => m.Id.Equals(id));

    public List<Movie> List() =>
        MovieRepository.Movies;
}
package ucsb.seclab.kerneline.github;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.kohsuke.github.GHCommit;
import org.kohsuke.github.GHException;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHUser;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.HttpException;

public class GithubDriver {

	private String githubRepoName;
	
	private GHRepository githubRepo;

	private GitHub github;
	
	private Map<String, GHCommit> commitsCache;
	
	private Map<String, GHUser> usersCache;
		
	public GithubDriver(String repo, String user, String password) throws IOException {
		this.github = GitHub.connectUsingPassword(user, password);
		this.githubRepoName = repo;
		this.githubRepo = this.github.getRepository(this.githubRepoName);
		this.commitsCache = new HashMap<String, GHCommit>();
		this.usersCache = new HashMap<String, GHUser>();
	}

	public Integer getUserFollowersCount(String userLogin) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(userLogin);
		if(user != null) {
			return user.getFollowersCount();
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Integer getUserFollowingCount(String userLogin) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(userLogin);
		if(user != null) {
			return user.getFollowingCount();
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Integer getUserPublicRepoCount(String userLogin) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(userLogin);
		if(user != null) {
			return user.getPublicRepoCount();
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Double getUserAverageStars(String u) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(u);
		if(user != null) {
			try {
				Double toReturn = 0.0;
				Map<String, GHRepository> repos = user.getRepositories();

				if (repos != null && !repos.isEmpty()) {
					for (String repo : repos.keySet()) {
						toReturn = toReturn + repos.get(repo).getStargazersCount();
					}

					return (toReturn / repos.size());
				} else {
					return null;
				}
			} catch (GHException e) {
				return null;
			}
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Double getUserAverageForks(String u) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(u);
		if(user != null) {
			try {
				Double toReturn = 0.0;
				Map<String, GHRepository> repos = user.getRepositories();

				if (repos != null && !repos.isEmpty()) {
					for (String repo : repos.keySet()) {
						toReturn = toReturn + repos.get(repo).getForks();
					}

					return (toReturn / repos.size());
				} else {
					return null;
				}
			} catch (GHException e) {
				return null;
			}
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Set<String> getCommitsAuthors(Set<String> commits) throws IOException {

		Set<String> authors = new HashSet<String>();
		GHUser tmpUser = null;
		for (String commit : commits) {
			GHCommit cached = this.commitsCache.get(commit);
			if(cached != null) {
				tmpUser = cached.getAuthor();
				// to handle cases in which the user is no longer in GitHub
				if (tmpUser != null) {
					authors.add(tmpUser.getLogin());
				}	
			} else {
				try {
					GHCommit toCache = this.githubRepo.getCommit(commit);
					tmpUser = toCache.getAuthor();
					this.commitsCache.put(toCache.getSHA1(), toCache);
					
					// to handle cases in which the user is no longer in GitHub
					if (tmpUser != null) {
						if(this.usersCache.get(tmpUser.getLogin()) == null) {
							this.usersCache.put(tmpUser.getLogin(), tmpUser);
						}
						authors.add(tmpUser.getLogin());
					}
				} catch (HttpException e) {
					// do nothing if wrong response from github for the current commit
				}	
			}
		}

		return authors;
	}

	public Double getUserAverageSubscribers(String u) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(u);
		if(user != null) {
			try {
				Double toReturn = 0.0;
				Map<String, GHRepository> repos = user.getRepositories();

				if (repos != null && !repos.isEmpty()) {
					for (String repo : repos.keySet()) {
						toReturn = toReturn + repos.get(repo).getSubscribersCount();
					}

					return (toReturn / repos.size());
				} else {
					return null;
				}
			} catch (GHException e) {
				return null;
			}
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Double getUserAverageWatchers(String u) throws IOException, UsersCacheMissException {
		GHUser user = this.usersCache.get(u);
		
		if(user != null) {
			try {
				Double toReturn = 0.0;
				Map<String, GHRepository> repos = user.getRepositories();

				if (repos != null && !repos.isEmpty()) {
					for (String repo : repos.keySet()) {
						toReturn = toReturn + repos.get(repo).getWatchers();
					}

					return (toReturn / repos.size());
				} else {
					return null;
				}
			} catch (GHException e) {
				return null;
			}
		} else {
			throw new UsersCacheMissException("GitHub user cache miss (should not be possible by design).");
		}
	}

	public Double getUsersAverageFollowersCount(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;

		for (String user : users) {
			toReturn = toReturn + this.getUserFollowersCount(user);
		}

		return toReturn / users.size();
	}

	public Double getUsersAverageFollowingCount(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;

		for (String user : users) {
			toReturn = toReturn + this.getUserFollowingCount(user);
		}

		return toReturn / users.size();
	}

	public Double getUsersAveragePublicRepoCount(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;

		for (String user : users) {
			toReturn = toReturn + this.getUserPublicRepoCount(user);
		}

		return toReturn / users.size();
	}

	public Double getUsersAverageStars(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;
		Double tmp;

		for (String user : users) {
			tmp = this.getUserAverageStars(user);
			if (tmp != null) {
				toReturn = toReturn + tmp;
			}
		}

		return toReturn / users.size();
	}

	public Double getUsersAverageForks(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;
		Double tmp;

		for (String user : users) {
			tmp = this.getUserAverageForks(user);
			if (tmp != null) {
				toReturn = toReturn + tmp;
			}
		}

		return toReturn / users.size();
	}

	public Double getUsersAverageSubscribers(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;
		Double tmp;

		for (String user : users) {
			tmp = this.getUserAverageSubscribers(user);
			if (tmp != null) {
				toReturn = toReturn + tmp;
			}
		}

		return toReturn / users.size();
	}

	public Double getUsersAverageWatchers(Set<String> users) throws IOException, UsersCacheMissException {
		Double toReturn = 0.0;
		Double tmp;

		for (String user : users) {
			tmp = this.getUserAverageWatchers(user);
			if (tmp != null) {
				toReturn = toReturn + tmp;
			}
		}

		return toReturn / users.size();
	}

}
